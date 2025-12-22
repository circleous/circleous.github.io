+++
title = 'CyberJawara 2021 Quals - PWN'
date = '2021-11-19T00:00:00+07:00'
tags = ['ctf-writeup', 'editorial', 'pwn']
draft = false
+++

Penulisan editorial berurut dari yang paling banyak dikerjakan sampai paling sedikit, _scroll_ ke bawah untuk detail cara mendapatkan bounty 100k GOPAY dari soal _quick maffs_. Any question? Discord: `circleous#0587`

## 1\. Heapnote

Bug pada soal terletak pada Use after Free, namun karena ukuran `malloc` statis perlu buat fake chunk terlebih dulu cukup besar untuk bisa mendapatkan unsorted bin. Detail writeup untuk soal tidak akan saya tulis karena writeup soal bertemakan heap ini sudah banyak. Tidak bermaksud untuk promosi :p, tapi series Linux Heap Exploitation dari Max Kamper [https://www.udemy.com/course/linux-heap-exploitation-part-1/](https://www.udemy.com/course/linux-heap-exploitation-part-1/) itu bagus untuk yang lebih enak belajar dengan video.

## 2\. Interview 101

Soal ini sebenernya dibuat untuk sebagai soal paling mudah di kualifikasi, tapi ternyata yang mengerjakan sampai dapat flag tidak sebanyak soal `heapnote`. Idenya user bisa melakukan _dynamic allocation_ di stack dimana bisa muncul out of bound rw access karena integer overflow saat alokasi. (size lebih dari ukuran buffer yang sebenarnya di alokasi).

```c
// size = 0x2000000000000001
// --> alloca(0x10000000000000010)
// --> alloca(0x10)
alloca(16 * ((8 * size + 23) / 0x10));
```

Namun, saat membuat soal ini saya justru menemukan bug lain yang bisa dilakukan.

```c
struct store_s {
  unsigned long size;
  char name[16];
  ...
}
...
void read_buf(char *prompt, char *buf, size_t sz) {
  printf("%s", prompt);
  fgets(buf, sz, stdin);

  int pos = strlen(buf) - 1;
  if (buf[pos] == '\n') {
    buf[pos] = 0;
  }
}
...
 store.size = read_uint("size = ");
 read_buf("storage name = ", store.name, sizeof(store.name) - 1);
...
```

Bug kedua ini karena bisa null byte overwrite pada store.size ketika [store.name](http://store.name) hanya berisikan null byte `\x00`. Kurang lebih begini skenarionya,

```c
store.size = read_uint("size = "); // 0x0A0000...
// ...
read_buf("storage name = ", store.name, sizeof(store.name) - 1);
// ...... di read_buf
   fgets(buf, sz, stdin); // store.name = "\x00"

   int pos = strlen(buf) - 1; // strlen(store.name) = 0, pos = -1
   if (buf[pos] == '\n') { // store.name[-1] == 0x0a / HSB dari store.size
     buf[pos] = 0; // store.size = 0x0000...
   }
// ......
```

Karena sudah bisa OOB (size gede banget, alokasi buffer kecil banget), tinggal leak dan overwrite saved RIP untuk ROP. Solve script, [https://gist.github.com/circleous/a65f9abb768c45bf1baa5017d2ec3f5d](https://gist.github.com/circleous/a65f9abb768c45bf1baa5017d2ec3f5d)

## 3\. Catch me if you can

Beberapa pekan lalu saya membuat soal backdoored qemu system escape untuk HackToday tahun ini, namun saya tarik kembali karena ternyata masih banyak masalah saat coba untuk dideploy. Ada niatan untuk release kembali soalnya untuk CJ tahun ini, tapi akhirnya saya buat lagi yang kurang lebih sama temanya. Soal ini banyak mengambil ide dari \*CTF 2021 - Favourite Architecture ([https://ctftime.org/task/14585](https://ctftime.org/task/14585)). Bedanya hanya pada restriksi syscall yang bisa dilakukan.

```diff
diff --git a/linux-user/syscall.c b/linux-user/syscall.c
index ccd3892b2..419c147a6 100644
--- a/linux-user/syscall.c
+++ b/linux-user/syscall.c
@@ -13144,8 +13144,19 @@ abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
         print_syscall(cpu_env, num, arg1, arg2, arg3, arg4, arg5, arg6);
     }
 
-    ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
-                      arg5, arg6, arg7, arg8);
+    switch (num) {
+        case TARGET_NR_read:
+        case TARGET_NR_write:
+        case TARGET_NR_exit:
+        case TARGET_NR_mprotect:
+            ret = do_syscall1(cpu_env, num, arg1, arg2, arg3,
+                              arg4, arg5, arg6, arg7, arg8);
+            break;
+        default:
+            printf("[!] %d bad system call\n", num);
+            ret = -1;
+            break;
+    }
 
     if (unlikely(qemu_loglevel_mask(LOG_STRACE))) {
         print_syscall_ret(cpu_env, num, ret, arg1, arg2,
```

Bug utama karena ada stack buffer overflow, jadi bisa melakukan ROP. Syscall `mprotect` bisa digunakan untuk membuat page `.bss` menjadi rwx pada context guest dan transfer dari ROP di stack ke shellcode di `.bss`. Selanjutnya untuk "escape" dari jail di qemu-user ini, ada beberapa cara. Intended solution menggunakan `mprotect` untuk infer address rwx qemu-user (code_gen_buffer) dan overwrite dengan shellcode execve. Solve script, [https://gist.github.com/circleous/652769c669d5dae83a4eacba0a824d44](https://gist.github.com/circleous/652769c669d5dae83a4eacba0a824d44)

## 4\. Trusted Note

Bug banyak karena intensinya juga dibuat untuk sebagai entry challenge di linux kernel module. Intinya dengan heap overflow overwrite pointer data dan ini bisa digunakan sebagai primitive untuk arbitrary read/write. Solve script dari ramdan tim hm apa ya, [https://gist.github.com/d4em0n/f94ee592ab4cc689cc91c95f7babbc67](https://gist.github.com/d4em0n/f94ee592ab4cc689cc91c95f7babbc67)

## 5\. Quick Maffs

v8 type confussion, TBD. Berhubung saya masih menjalankan bounty (100k GOPAY atau e-wallet lain) untuk soal ini sampai Final Cyber Jawara 2021 (1 Desember 2021), editorial dari saya akan dirilis setelah Final CJ 2021 selesai. Rule cukup simple,

1. ~~Kirim flag ke saya (`circleous#0587`) lewat Discord~~. Bounty taken by Linuz
2. Tidak curang dan tidak berbagi flag, saya akan menanyakan beberapa hal untuk konfirmasi