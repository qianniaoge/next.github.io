---
title: how2heap - double free
categories:
  - how2heap
tags: null
published: true
---

# Overview

- [fastbin_dup.c](https://github.com/shellphish/how2heap/blob/master/fastbin_dup.c)

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
```

# Double Free

多次释放同一块内存可以导致内存泄露。内存分配的数据结构被攻击者破坏并且可以被利用。在下面的程序示例中，一个 fastbin chunk 被释放了两次，为了避免 glibc 'double free or corruption (fasttop)' 的安全检查，两次释放的中间必须有另外一块 fastbin chunk 被释放。这意味着同样一块内存返回给了两次不同的分配。它们的指针都指向同一块内存。如果其中一个收到攻击者的控制，他/她就可以修改内存从而导致多种攻击（包括代码执行）。

查看一下示例代码：

```c
a = malloc(10);     // 0xa04010
b = malloc(10);     // 0xa04030
c = malloc(10);     // 0xa04050

free(a);
free(b);  // To bypass "double free or corruption (fasttop)" check
free(a);  // Double Free !!

d = malloc(10);     // 0xa04010
e = malloc(10);     // 0xa04030
f = malloc(10);     // 0xa04010   - Same as 'd' !
```

fastbin 的变化：

1. 'a' freed.
  > head -> a -> tail
2. 'b' freed.
  > head -> b -> a -> tail
3. 'a' freed again.
  > head -> a -> b -> a -> tail
4. 'malloc' request for 'd'.
  > head -> b -> a -> tail      [ 'a' is returned ]
5. 'malloc' request for 'e'.
  > head -> a -> tail           [ 'b' is returned ]
6. 'malloc' request for 'f'.
  > head -> tail                [ 'a' is returned ]

现在，'d' 和 'f' 指针指向同一块内存地址，任何一个改变了都会影响到另一个。

不过这种特殊的例子在 smallbin 中不会有效。第一次释放时 'a' 的 next chunk 会清除 PREV_INUSE 标志位，当第二次释放时，会报 "double free or corruption (!prev)" 错误。