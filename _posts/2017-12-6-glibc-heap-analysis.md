---
title: glibc heap analysis
categories:
  - heap-exploitation
tags: null
published: true
---

# 0x00 What is heap?

堆是程序在运行时创建的一块内存空间，用于存储动态分配内存的变量，能够全局访问。

`stdlib.h` 提供的标准库函数 **malloc** 和 **free** 用来管理堆内存。

glibc-2.24 `malloc.c` 提供的文档（本文参照的 malloc.c 为 glibc-2.24 版本）：
- **malloc** (malloc.c # 523):	
	```c
	/*
	  malloc(size_t n)
	  Returns a pointer to a newly allocated chunk of at least n bytes, or null
	  if no space is available. Additionally, on failure, errno is
	  set to ENOMEM on ANSI C systems.
	
	  If n is zero, malloc returns a minumum-sized chunk. (The minimum
	  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
	  systems.)  On most systems, size_t is an unsigned type, so calls
	  with negative arguments are interpreted as requests for huge amounts
	  of space, which will often fail. The maximum supported value of n
	  differs across systems, but is in all cases less than the maximum
	  representable value of a size_t.
	*/
	```
- **free** (# malloc.c 540):
	```c
	/*
	  free(void* p)
	  Releases the chunk of memory pointed to by p, that had been previously
	  allocated using malloc or a related routine such as realloc.
	  It has no effect if p is null. It can have arbitrary (i.e., bad!)
	  effects if p has already been freed.
	
	  Unless disabled (using mallopt), freeing very large spaces will
	  when possible, automatically trigger operations that give
	  back unused memory to the system, thus reducing program footprint.
	*/
	```

关于堆的 memory allocators：
- dlmalloc - General purpose allocator
- ptmalloc2 - glibc
- jemalloc - FreeBSD and Firefox
- tcmalloc - Google
- libumem - Solaris
- Magazine malloc - IOS/OSX
- ...

# 0x01 Heap Creation

**malloc** 使用系统调用 [brk](http://man7.org/linux/man-pages/man2/sbrk.2.html) 和
 [mmap](http://man7.org/linux/man-pages/man2/mmap.2.html) 从操作系统处获取内存
  （ brk()为系统调用，sbrk()为glibc 函数 ）

**brk**:

初始状态下:
- start_brk 指向 数据段/bss段 的末尾，即 end_data
- brk（堆的末尾）初始值等于start_brk，也就是初始状态下堆区大小为0

brk() 改变 program break(brk) 的位置来分配或释放内存，

sbrk() 的 increment 为正或负则增加或减小堆的大小，若为0则返回当前 brk 的值

- 当 ASLR 关闭时，初始状态下的 start_brk 和 brk 指向 数据段/bss段 的末尾
- 当 ASLR 开启时，初始状态下的 start_brk 和 brk 指向 数据段/bss段 的末尾再加上一段随机大小的偏移

![linux flexible address space layout]({{ site.baseurl }}/images/linuxFlexibleAddressSpaceLayout.png)

（ brk()/sbrk()只在主线程中调用 ）

**mmap**:

malloc 调用 mmap 创建一个私有且匿名的映射内存，将文件或其它对象映射进内存，分配该内存的进程独占使用这块内存。函数定义如下：

{% highlight c %}
#include <sys/mman.h>

void *mmap(void *addr, size_t length, int prot, int flags,
			int fd, off_t offset);
int munmap(void *addr, size_t length);
{% endhighlight %}

# 0x02 Heap Organization

## Arena

glibc 的 ptmalloc 基于 dlmalloc 增加了多线程支持，帮助内存分配器更高效的执行，为了避免不必要的向内核申请内存，每个线程都有自己的分配区( arena )，arena 是 heap segment 中除了已使用部分（ heap ）外所剩余的内存区域，一般会在程序首次调用 malloc 后分配一定量的内存，为进程后续调用 malloc 做准备。

![arena and heap in heap segment]({{site.baseurl}}/images/arena_and_heap.png)

虽然每个线程都有独立的 arena ，但是 arena 的数量是有限制的。

- For 32 bit systems：

	Number of arena = 2 * number of cores + 1.

- For 64 bit systems：

	Number of arena = 8 * number of cores + 1.

主线程的 arena 叫做主分配区（ main arena ），其它线程的 arena 则是非主分配区（ non main arena ）。一个进程可以有多个 non main arena，但只有一个 main arena。main arena 与 non  main arena 用环形链表进行管理，每一个分配区利用互斥锁（ mutex ）使线程对该分配区的访问互斥。

main arena 可以访问进程的 heap 区域和 mmap 映射区域，也就是 main arena 可以调用 sbrk() 和
 mmap() 函数向操作系统申请内存，而 non main arena 只能访问进程的 mmap 映射区域，
 non main arena 每次使用 mmap() 申请 HEAP_MAX_SIZE （32位系统默认位1MB，64位系统默认为64MB）大小的内存。

## Heap Structures

在分析 glibc 内存管理之前需要知道：

ptmalloc 使用宏来屏蔽不同平台的差异，将 INTERNAL_SIZE_T 定义为 size_t ， SIZE_SZ 定义为 size_t 的大小，在 32 位平台下为 4 字节，在 64 位平台下为 4 字节或者 8 字节。另外分配 chunk 时必须以 2* SIZE_SZ 对齐32 平台 chunk 地址按 8 字节对齐， 64 位平台按 8 字节或是 16 字节对齐

- heap

	由许多连续的 chunk 组成的内存区域，每个 heap 只属于一个 arena。( heap != heap segment)

- heap_info

	即 Heap Header，一个 thread arena 可以包含多个 heaps，为了便于管理，就给每个 heap 分配一个 heap header。为什么会包含多个 heaps？在当前 heap 不够用时 malloc 会通过系统调用 mmap 申请新的 heap（ 和原 heap 不相邻 ）。
	
	```c
	typedef struct _heap_info
	{
	  mstate ar_ptr; /* Arena for this heap. */
	  struct _heap_info *prev; /* Previous heap. */
	  size_t size;   /* Current size in bytes. */
	  size_t mprotect_size; /* Size in bytes that has been mprotected
		                   PROT_READ|PROT_WRITE.  */
	  /* Make sure the following data is properly aligned, particularly
	     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
	     MALLOC_ALIGNMENT. */
	  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
	} heap_info;
	```

- binmap

	binmap 字段是一个 int 数组，ptmalloc 用一个 bit 来标识该 bit 对应的 bin 中是否包含空闲的 chunk。
	
	malloc.c # 1550
	
	```c
	/*
	   Binmap

	    To help compensate for the large number of bins, a one-level index
	    structure is used for bin-by-bin searching.  `binmap' is a
	    bitvector recording whether bins are definitely empty so they can
	    be skipped over during during traversals.  The bits are NOT always
	    cleared as soon as bins are empty, but instead only
	    when they are noticed to be empty during traversal in malloc.
	 */

	/* Conservatively use 32 bits per map word, even if on 64bit system */
	#define BINMAPSHIFT      5
	#define BITSPERMAP       (1U << BINMAPSHIFT)
	#define BINMAPSIZE       (NBINS / BITSPERMAP)

	#define idx2block(i)     ((i) >> BINMAPSHIFT)
	#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

	#define mark_bin(m, i)    ((m)->binmap[idx2block (i)] |= idx2bit (i))
	#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
	#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))
	```

- malloc_state

	即 Arena Header，一个线程包含的每个 heap 都只有一个 arena header 存在。Arena header 包含 bins 、top chunk 以及最后一个 remainder chunk 等（这些概念在后文介绍）。

	malloc.c # 1675
	```c
	struct malloc_state
	{
	  /* Serialize access.  */
	  mutex_t mutex;

	  /* Flags (formerly in max_fast).  */
	  int flags;

	  /* Fastbins */
	  mfastbinptr fastbinsY[NFASTBINS];

	  /* Base of the topmost chunk -- not otherwise kept in a bin */
	  mchunkptr top;

	  /* The remainder from the most recent split of a small request */
	  mchunkptr last_remainder;

	  /* Normal bins packed as described above */
	  mchunkptr bins[NBINS * 2 - 2];

	  /* Bitmap of bins */
	  unsigned int binmap[BINMAPSIZE];

	  /* Linked list */
	  struct malloc_state *next;

	  /* Linked list for free arenas.  */
	  struct malloc_state *next_free;

	  /* Memory allocated from the system in this arena.  */
	  INTERNAL_SIZE_T system_mem;
	  INTERNAL_SIZE_T max_system_mem;
	};
	```

- malloc_chunk

	即 Chunke Header，一个 heap 被分为多个根据用户申请大小的 chunk，每个 chunk 都有自己的 chunk header。

	malloc.c # 1093
	```c
	struct malloc_chunk {

	  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
	  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

	  struct malloc_chunk* fd;         /* double links -- used only if free. */
	  struct malloc_chunk* bk;

	  /* Only used for large blocks: pointer to next larger size.  */
	  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
	  struct malloc_chunk* bk_nextsize;
	};
	```

 NOTE:

1. Main thread 不含有多个 heaps 所以也就不含有 heap_info 结构体。当需要更多堆空间的时候，就通过扩展 sbrk 的 heap segment 来获取更多的空间，直到它碰到内存 mapping 区域为止。

2. 不同于 thread arena，main arena 的 arena header 并不是 sbrk heap segment 的一部分，而是一个全局变量，因此它属于 libc.so 的 data segment。 

图解 mian arena 与 thread arena（单个 heap segment）：

![]({{site.baseurl}}/images/sQj8dLRIGudo7SihLqOIzvQ.png)

图解 thread areana （多个 heap segments）：

![]({{site.baseurl}}/images/s-BNoTUisiIgfyaQBplNGXw.png)

## Chunk

在 glibc malloc 中将整个堆内存空间分成了连续的、大小不一的 chunk，即对于堆内存管理而言 chunk 就是最小的操作单位。

在 heap  segment 中的 chunk 可以分为以下4类：

- Allocated chunk
- Free chunk
- Top chunk
- Last Remainder chunk

### Allocated chunk

{% highlight c %}
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |N|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |N|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
{% endhighlight %}

在 glibc `malloc.c` 中可以查看到相关文档 ( glibc 2.24 - malloc.c # 1093）

prev_size: 如果前一个 chunk 是空闲的，该域表示前一个 chunk 的大小，如果前一个 chunk 处于已分配状态，该域则包含前一个 chunk 的用户数据。

size: 当前 chunk 的大小，最后 3 bits 包含标志信息。

- PREV_INUSE (P) - 前一个 chunk 已分配则设为 1

- IS_MMAPPED (M) - 当前 chunk 是通过 mmap 分配的则设为 1

- NON_MAIN_ARENA (N) - 当前 chunk 属于 thread arena 则设为 1

### Free chunk

{% highlight c %}
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |N|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |N|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
{% endhighlight %}

相邻的两个 free chunk 会合并在一起，所以不会有连续的两个 free chunk。当 chunk 空闲时，fd 和 bk 才存在。

fd: Forward pointer - 前向指针 fd 指向双向链表 bin 中的前一个 free chunk。

bk: Backward pointer - 后向指针  bk 指向双向链表 bin 中的后一个 free chunk。

fd_nextsize: 如果当前 chunk 存在于 large bins 中时，fd_nextsize 指向下一个比当前 chunk 大小大的第一个 free chunk。

bk_nextsize: 如果当前 chunk 存在于 large bins 中时，bk_nextsize 指向上一个比当前 chunk 大小小的第一个 free chunk。

**Space Reuse**

对于正在使用的 chunk，它的下一个 chunk 的 prev_size 是无效的，这块内存也可以被当前 chunk 使用，因此对于使用中的 chunk 大小计算公式是：chunk_size = （用户请求大小 + (2 -1) * sizeof(INTERNAL_SIZE_T)) aligh to 2 * sizeof(size_t)。可以参考 `malloc.c # 92`。

## Bins

bin 是一种记录 free chunk 的链表数据结构。对于空闲的 chunk，ptmalloc 采用分箱式内存管理方式，根据空闲 chunk 的大小，将其放在四个不同的 bin 中：

- Fast bin

- Unsorted bin

- Small bin

- Large bin

在 glibc 中用于记录 bin 的数据结构有两种：

**fastbinsY**: 存储 LIFO 单链表的数组，记录所有的 fast bins。

**bins**: 数组的每个索引都是一个 FIFO 双向链表，用于记录除 fast bins 之外的所有bins。

事实上，一共有126个 bins，分别是：

- bins[0] 并不存在 (malloc.c # 1459)
- bins[1] - Unsorted bin
- bins[2] 到 bins[63] - Small bin
- bins[64] 到 bins[126] - Large bin

### Fast Bin

32位系统下大小为 16 到 80 bytes，64位系统下大小位 32 到 160 bytes 的 chunk 称为 fast chunk。fast bin 记录空闲状态的 fast chunk，用于提高小内存的分配效率。

- Number of bins - 10

	每个 fast bin 都是一个单链表（只使用 fd 指针），在 fast bin 中无论是添加还是移除 fast chunk，都是对头部（从上往下看）进行操作 - LIFO（后进先出）。

- Chunk size 

	fast bin中所包含的fast chunk size是按照步进8字节排列的，即第一个fast bin中所有fast chunk size均为16字节，第二个fast bin中为24字节，依次类推。每个 fast bin 记录的都是大小相同的 chunk。

- No Coalescing

	两个相邻的 fast chunk 不会进行合并操作，其 chunk size 的 P 标志位总是设置为1。

- malloc (fast chunk)

	在初始化时 fast bin 支持的最大内存大小以及所有 fast bin 链表都是空的，所以即使用户申请了一个 fast chunk，它也不会交由 fast bin 来处理，而是向下传递交由 smallo bin 来处理，如果 small bin 也为空的话就交给 unsorted bin 来处理。

	那么 fast bin 是在哪？怎么进行初始化的呢？当我们第一次调用 malloc (fast chunk) 的时候，系统执行 _int_malloc 函数，该函数首先会发现当前 fast bin 为空，就转交给 small bin 处理，进而又发现 small bin 也为空，就调用 malloc_consolidate 函数对 malloc_state 结构体进行初始化， malloc_consolidate 函数主要完成以下几个功能：

	1. 首先判断当前 malloc_state 结构体中的 fast bin 是否为空，如果为空就说明整个 malloc_state 都没有完成初始化，
	需要对 malloc_state 进行初始化。

	2. malloc_state 的初始化操作由函数 malloc_init_state(msate av) 完成，该函数先初始化除 fast bin 之外的所有 bins
	（构建双链表），再初始化 fast bins。

	之后当 fast bin 中的相关数据不为空了，就开始使用 fast bin。

	得到第一个来自于 fast bin 的 chunk 之后，系统就将该 chunk 从对应的 fast bin 中移除，并将其地址返回给用户。

- free (fast chunk)

	先通过 chunksize 函数根据传入的地址指针对应的 chunk 的大小，然后根据这个 chunk 的大小获取该 chunk 所属的 fast bin，然后再将此 chunk 添加到该 fast bin 的链尾。

在 main arena 中 fast bins 的整体操作示意图如下图所示：

![]({{site.baseurl}}/images/sRV48m6inD0d7vdT83qziBw.png)

### Unsorted Bin

当 small chunk 或者 large chunk 释放的时候，会先放到 unsorted bin 中，分配时，如果在 unsorted bin 中没有合适的 chunk，就会把 unsorted bin 中所有 chunk 分别加入到所属的 bin 中，然后再从 bin 中分配合适的 chunk。

- Number of bins - 1

	Unsoted bin 是一个有 free chunks 组成的循环双向链表。

- Chunk size: 在 unsorted bin 中，对 chunk 的大小没有限制，任何大小的 chunk 都可以归属到 unsorted bin 中。

### Small bin

32 位系统下小于512字节的 chunk，64位系统下小于1024字节的 chunk 称之为 small chunk，small bin 就是用于管理 small chunk 的。就内存分配和释放的速度而言，small bin 比 larger bin 快，但比 fast bin 慢。

- Number of bins - 62

	每个 small bin 也是一个由对应 free chunk 组成的循环双向链表。同时 small bin 采用 FIFO（先进先出）算法，内存释放操作就将新释放的 chunk 插入到链表的头部，内存分配操作就从链表的尾部移除 chunk（本文所指的头部尾部是以从上往下看的角度，参照 large bin 配图）。

- Chunk Size

	同一个 small bin 中所有 chunk 的大小是一样的，且第一个 small bin 中 chunk 大小位 16 字节，后续每个 small bin 中 chunk 的大小一次增加 8 字节，以此类推。

- Coalescing

	相邻的 free chunk 会合并成一个 free chunk。

- malloc(small chunk)

	最初所有的 small bin 都是空的，因此在对这些 small bin 完成初始化之前，即使用户请求的内存大小属于 small chunk 也不会交由 small bin 进行处理，而是交由 unsorted bin 处理，如果 unsorted bin 也不能处理的话，glibc 就以此遍历后续的所有 bins，找出第一个满足要求的 bin，如果所有的 bin 都不满足的话，就转而使用 top chunk，如果 top chunk大小不够，那么就扩充 top chunk，这样就一定能满足需求了。

	在第一次调用 malloc 时，初始 malloc_state 的时候对 small bin 和 large bin 进行初始化，bin 的指针指向自己表明为空。(malloc.c # 1808)

	之后，当再次调用 malloc(small chunk) 的时候，如果该 chunk size 对应的 small bin 不为空，就从该 small bin 链表中取得 small chunk，否则就需要交给 unsorted bin 及之后的逻辑来处理了。

- free(small chunk)

	当释放 small chunk 时，检查它前一个或后一个 chunk 是否空闲，如果是，则合并到一起：将其从 bin 中移除，合并成新的 chunk，最后将新的 chunk 添加到 unsorted bin 中。

### Large bin

32位系统下大于等于512字节，64位系统下大于等于1024字节的 chunk 称为 large chunk，large bin 就是用于管理这些 large chunk 的。

- Number of bins - 63

	large bins 一共包括63个 bin，每个 bin 都是一个双向链表，同一个 large bin 可以拥有不同大小的 chunk，从大到小依次递减（最大的 chunk 在链表头部，最小的 chunk 在链表尾部）。large bin 的任何位置都可以添加和移除 large chunk。

	在这63个 large bins 中，每个 bin 中的 chunk 大小不是一个固定公差的等差数列，而是分成6组 bin，每组 bin 是一个固定公差的等差数列。前32个 bins 以64字节为间隔，每个 large bin 中的 chunk 又是以8字节为间隔，即第一个 large bin 中 chunk size 为 512 - 568 字节 ...

	To summarize:

	```c
	No. of Bins       Spacing between bins
	64 bins of size       8  [ Small bins]
	// NBINS 定义为128， 其实 bin[0] 和 bin[127]都不存在， bin[1]为 unsorted bin。
	32 bins of size      64  [ Large bins]
	16 bins of size     512  [ Large bins]
	8 bins of size     4096  [ ..        ]
	4 bins of size    32768
	2 bins of size   262144
	1 bin  of size what's left
	```

- Coalescing

	两个 free chunk 不能相邻存放在一起，他们会进行合并。

- malloc(large chunk)

	初始时全部的 large bins 都为空，即使用户申请了一个 large chunk，不是给 large bin 进行处理，而是交由 next largest bin (**to do**) 进行处理，初始化操作与 small bin 一致。

	之后当用户再次请求一个 large bin时，首先确定用户请求的大小属于哪一个 large bin，然后判断该 large bin 中最大的 chunk 的大小是否大于用户请求的大小。

	如果大于，就从尾部到头部遍历该 large bin，找到一个大小相等或接近的 chunk 返回给用户。如果该 chunk 大于用户请求的大小的话，就将该 chunk 拆分为两个 chunk：前者返回给用户，且大小等同于用户请求的大小，剩余的部分作为一个新的 chunk 添加到 unsorted bin 中。

	如果该 large bin 中最大的 chunk 小于用户请求的大小，那么就依次查看后续不为空的 large bin 中是否有满足需求的 chunk，如果找到合适的，切割之后返回给用户。如果没有找到，尝试交由 top chunk 处理。

- free(large chunk)

	与 small chunk 相似。

![]({{site.baseurl}}/images/sOKHm_YojzekopUlsZWBPEw.png)

## Top Chunk

top chunk 位于 arena 的顶部。它不属于任何 bin。Top chunk 用于服务其它 bins 都无法满足的用户请求，如果 top chunk 大于用户请求的大小，它会分出一部分内存给用户成为 user chunk，剩下的部分则成为新的 top chunk。如果 top chunk 小于用户请求的大小，ptmalloc 会调用 sbrk (main arena) 或者 mmap (thread arena) 来扩展 top chunk 的大小。与 top chunk 相邻的 free chunk 会与 top chunk 合并， top chunk 的 PREV_INUSE 标志位永远设置为1。

## Last Remainder Chunk

这是最近一次 small chunk 请求而产生分割后剩下的那一块 chunk，当在 small bins 和 unsorted bin 中找不到合适的 chunk时，如果 last remainder chunk 的大小大于用户请求的大小，则将其分割，返回用户所需 chunk 后，剩下的成为新的 last remainder chunk。

# 0x03 Glibc malloc algorithm

## arena_get

**arena_get (ar_ptr, size)**

获得一块 arena 并加上锁。将`ar_ptr` 设置成指向相应 arena 的指针。`size`只是一个参照，表示现在需要多少内存。

## sysmalloc [TODO]

**void * sysmalloc (INTERNAL_SIZE_T nb, mstate av)**

(malloc.c # 2266)

sysmalloc 用于当 malloc 需要从操作系统处获取更多内存时调用，比如说当 top chunk 没有足够的内存时，就需要调用它来扩展 top chunk 或者替换一个 top chunk。

## alloc_perturb [TODO]

**void alloc_perturb (char *p, size_t n)**	(mallo.c # 1883)

**void free_perturb (char *p, size_t n)**

将已申请或已释放的内存标志为已申请（用户还未使用）或已释放状态（表示不是未初始化状态）。

## unlink

**unlink(AV, P, BK, FD)**

这是一个用来将 chunk 从 bin 中移除的宏定义。 (malloc.c # 1406)

1. 检查 chunk size 是否等于相邻的下一个 chunk 的 previous size 域的值，如果不等于，则抛出 ("corrupted size vs. prev_size") 异常。（引用自参考资料，暂未查证源码）

2. 检查 `P->fd->bk == P` 和 `P->bk->fd == P`。如果不等于，则抛出 ("corrupted double-linked list") 异常。

3. 调整列表中相邻块的前向和后向指针：

	```c
	P->fd->bk = P->bk;
	P->bk->fd = P->fd;
	```

4. 如果 chunk size 不为 small chunk 并且 `P->fd_nextsize != NULL`，则继续。

5. 检查 `P->fd_nextsize->bk_nextsize != P` 或者 `P->bk_nextsize->fd_nextsize != P)`，如果不等于成立，则抛出 ("corrupted double-linked list (not small)") 异常。

6. 判断 `p->fd->fd_nextsize == NULL`。

7. 如果等于，则检查 `P->fd_nextsize == P`。

	如果成立，则执行：

	```c
	P->fd->fd_nextsize = P->fd->bk_nextsize = P->fd;
	```

	如果不成立，则执行：

	```c
	P->fd->fd_nextsize = P->fd_nextsize;
	P->fd->bk_nextsize = P->bk_nextsize;
	P->fd_nextsize->bk_nextsize = P->fd;
	P->bk_nextsize->fd_nextsize = P->fd;
	```

8. 如果不等于，则执行：

	```c
	P->fd_nextsize->bk_nextsize = P->bk_nextsize;
	P->bk_nextsize->fd_nextsize = P->fd_nextsize;
	```

## malloc_consolidate

**void malloc_consolidate(mstate av)**

相当于 free() 的特殊版本。(malloc.c # 4143)

1. 检查 `global_max_fast` 是否为0 (av 未初始化)，如果为0，调用 `malloc_init_state` 初始化 `av` (malloc_state)，函数调用结束。

2. 如果 `global_max_fast` 不为0，则清除 `av` 的 `FASTCHUNKS_BIT`。

3. 遍历 fast bin 中的每一个 chunk：

	```
        i. 给当前 fast bin 的 chunk 加锁，如果不为空，则继续。

       ii. 如果上一个 chunk 并未使用，则调用 `unlink ` 移除前一个 chunk。

      iii. 如果下一个 chunk 不是 top chunk：

	        i. 如果下一个 chunk 并未使用，调用 `unlink` 移除下一个 chunk。
	       ii. 如果下一个 chunk 已使用则将合并后的 chunk （如果之前 unlink 了上一个chunk）添加到 unsorted bin 的头部。

     iiii. 如果下一个 chunk 是 top chunk，则与 top chunk 合并成新的 top chunk。
	```

## malloc

- **void * _int_malloc (mstate av, size_t bytes)**

	函数体在 (malloc.c # 3348)

ptmalloc 响应用户内存分配要求的具体步骤为：

1. 获取分配区的锁，为了防止多个线程同时访问同一个分配区，在进行分配前需要取得分配区域的锁，线程先查看线程私有实例中是否已经存在一个分配区，如果存在，尝试对该分配区加锁，如果加锁成功，使用该分配区分配内存，否则，该线程搜索分配区循环链表试图获得一个空闲（没有加锁）的分配区。如果所有的分配区都已经加锁，那么 ptmalloc 会开辟一个新的分配区，把该分配区加入到全局分配区循环链表和线程的私有实例中并加锁，然后使用该分配区进行分配操作。开辟出来的新分配区一定为非主分配区，因为主分配区是从父进程那里继承来的。开辟非主分配区时会调用 mmap() 创建一个 sub-heap，并设置好 top chunk。(这一步操作实际是在调用 _int_malloc() 之前完成的，但也属于 malloc 部分，之后的步骤为 _int_malloc 函数的具体步骤）

2. 将用户请求大小转换为实际需要分配的 chunk 空间大小，具体查看 request2size 宏 (malloc.c # 1243)。

3. 查看当前分配区是否可用 (空间是否足够），若不可用则回退到（调用） sysmalloc 从 mmap（映射区）获得一个 chunk 并调用 `alloc_perturb`（用作 debug 的宏）返回给用户。

4. 判断所需分配 chunk 的大小是否属于 fastbin 的范围，如果是则执行：

	```
        i. 根据需要的大小在 fastbin 数组中获取合适的 bin 的索引。

       ii. 移除 bin 中第一个 chunk 并且让 `victim` (bin index) 指向该 bin。

      iii. 如果 `victim` 为空，则执行第5步。

      iv. 如果 `victim` 不为空，检查所需 chunk 大小是否为该 bin，否则抛出（“malloc(): memory corruption (fast)") 异常

       v. 调用 `alloc_perturb`，并返回指向分配的 chunk 的指针。
	```

5. 判断所需分配的 chunk 的大小是否属于 smallbin 的范围，

	如果是则执行：

	        i. 根据需要的大小在 smallbin 数组中获取合适的 bin 的索引。

	       ii. 如果该 bin 中没有 chunk 则执行第7步。

	      iii. 让`victim` 等于 bin 尾部的最后一个 chunk，如果该 bin 为空（发生在初始化期间），则调用 malloc_consolidate 
	      	并转向第7步。

	      iv. 如果该 bin 不为空，检查 `victim->bk->fd` 是否等于 `victim`，如果不等于则抛出 ("malloc(): smallbin double 
	      	linked list corrupted") 异常。

	       v. 设置 `victim` 的 next chunk（在堆内存中，不是在链表中）的 PREV_INUSE 标志位为1。

	      vi. 将该 chunk 从链表中移除。

	     vii. 根据 malloc_state 设置该 chunk 的 arena 位的值。

	    viii. 调用 `alloc_perturb` 并返回指针。

	如果不是，则执行：

	        i. 根据需要的大小在 largebin 数组中获取合适的 bin 的索引。

	       ii. 检查 `av` 是否有 fastchunks，如果有，则调用 malloc_consolidate 将相邻的空闲 fast chunk进行合并。

6. 如果现在为止还未返回合适 chunk 的指针，这意味着有以下几种情况：

	```
        i. 所需 chunk 大小属于 fastbin 的范围，但是没有可用的 fast chunk。

       ii. 所需 chunk 大小属于 smallbin 的范围，但是没有可用的 small chunk。

      iii. 所需 chunk 为 large chunk。
	```

7. 查看 unsorted chunks 并将他们放入对应的 bin中，这是唯一将 chunk 放入 bins 中的地方。从尾部开始遍历 unsorted bin。

	```
        i. 将`victim` 指向当前遍历的 chunk。

       ii. 检查 `victim` 指向的 chunk size 是否在最小值 (2*SIZE_SZ) 与最大值 (av->system_mem) 的范围内，否则报错
       	 ("malloc(): memory corruption") 。

      iii. 如果（请求的 chunk 大小在 smallbin 范围内）and（`victim` 为 last remainder chunk）and（当前 chunk 是
      	unsorted bin 中唯一的 chunk）and （当前 chunk size >= 请求的 chunk size），则将当前 chunk 分为两块。
      		- 第一块为用户请求的 chunk 大小并返回给用户。
      		- 剩下的一块成为新的 last remainder chunk，放入 unsorted bin 中（如果剩下的那块属于 largebin 的范围
      		，则还要清除 fd_nextsize、bk_nextsize）。
			  i. 再将两块 chunk 的 chunk_size 域和 chunk_prev_size 域设置为正确的值。
			 ii. 第一块 chunk 在调用 `alloc_perturb` 后返回。

      iv. 如果上面的判断不成立，则程序执行到这里。将 `victim` 从 unsorted bin 中移除。如果 `victim` (当前 chunk) 的
      	大小与所请求的大小匹配，则调用 `alloc_perturb` 后返回。

       v. 如果 `victim` 的大小属于 smallbin 的范围，则将其插入到 smallbin 的尾部。

      vi. 否则将其插入到 largbin 中同时保持排序顺序（从上往下看为从大到小）：
      		- 首先检查 `largbin->bk` (最小的 large chunk）是否比 `victim` 大，如果是则将 `victim` 插入到
      		 `largebin->bk`后面，成为最小的 large chunk。
      		- 否则，就循环直到当前 chunk size >= victim 的 chunk size，将 `victim` 插入到当前 chunk 的前面。

     vii. 重复整个步骤 `MAX_ITERS (10000)` 次或者直到 unsorted bin 中所有的 chunks 都遍历完了。
	```

8. 查看过 unsorted bins，再检查请求的 chunk size 是否属于 small bin 范围，如果不是，则查看 largebins。

	```
        i. 根据需要的大小在 largebin 数组中获取合适的 bin 的索引。

       ii. 如果 large bin 不为空且最大的 large chunk (largebin 头部的 chunk）比请求的大小大则：
       		i. 从尾部开始循环直到找到一个最小的 chunk (`victim`) 大于等于请求的大小。
       	       ii. 调用 unlink 从 large bin 中移除该 chunk。
       	      iii. 计算 `remainder_size` ( victim 的 chunk size 减去请求的 chunk size)。
       	       iv. 如果 `remainder size >= MINSIZE` 则将其分成两块。否则，返回整块 `victim` chunk 。
       	       	若分出了 remainder chunk 则将其插入到 unsorted bin 的头部，插入前会检查是否
       	       	`unsorted_chunks(av)->fd->bk == unsorted_chunks(av)`（ unsorted_chunks(av) 返回的是指向
       	       	unsorted bin 头部的指针），否则抛出 ("malloc(): corrupted unsorted chunks") 异常。
       	       	v. 调用 alloc_perturb 后返回 `victim`。
	```

9. 到现在为止，已经查找过 unsorted bin、fast bin、small 和 large bin。也准确查找了 fast 或 small bin 中是否有所需 chunk。重复以下步骤直到所有的 bins 都查找完：

	```
        i. 增加 bin 数组的索引，移向下一个 bin。

       ii. 使用 `av->binmap` 跳过空的 bin。

      iii. 将 `victim` 指向当前 bin 的尾部。

       iv. 使用 binmap 确认跳过的 bin 是空的。然而，并不能确定所有空的 bin 都被跳过了。检查 `victim` 所在的 bin 是否为空。
      	 如果为空，则继续跳过，持续以上步骤直到找到不为空的 bin。

       v. (暂未理解为何能直接分割）将 `victim` 分割，并调用 unlink 移除返回的 chunk。若 remainder chunk 大于 MINSIZE，
       	则将其插入 unsorted bin 的头部，插入之前检查 `unsorted_chunks(av)->fd->bk` 是否等于 unsorted_chunks(av)，
       	否则抛出 ("malloc(): corrupted unsorted chunks 2") 异常。

      vi. 如果请求的大小属于 smallbin 范围，则分割后的 remainder chunk 成为新的 last remainder chunk，如果不属于
      	smallbin 则将 fd_nextsize、bk_nextsize 清空。最后调用 alloc_perturb 返回指针。
	```

10. 如果还不能找到，则使用 top chunk 满足需求：

	```
        i. victim 指向 av->top。

       ii. 如果 top chunk >= 请求的大小 + MINSIZE，则分割成两块 chunk。这里的 remainder chunk 成为新的 top chunk，另一个
       	在调用 alloc_perturb 后返回给用户。

      iii. 查看 `av` 是否有 fastchunks，这是查看 `av->flags`的 FASTCHUNKS_BIT 完成的操作。如果有，就调用
      	malloc_consolidate 合并 fastchunks，并转向第7步（查找 unsorted bin）。

       iv. 如果 `av` 没有 fastchunks，调用 sysmalloc 获取 chunk 并在调用 alloc_perturb 后返回指针。
	```
（此时 _int_malloc 函数已经全部执行，以下步骤为 sysmalloc 调用）

11. 当调用 sysmalloc 向系统申请分配是有两个选择：如果是主分配区，调用 sbrk() 增加 top chunk 大小；如果是非主分配区，调用 mmap 来分配一个新的 sub-heap，增加 top chunk 大小；或者使用 mmap() 来直接分配。在这里，需要依靠 chunk 的大小来决定到底使用哪种方法。判断所需分配的 chunk 大小是否大于等于 mmap 分配阈值，如果是的话，则转下一步，调用 mmap 分配，否则转到13步。

12. 使用 mmap 系统调用为程序的内存空间映射一块 chunk_size aligh 4KB 大小的空间。然后将内存指针返回给用户。

13. 判断是否为第一次调用 malloc，若是主分配区，则需要进行一次初始化工作，分配一块大小为 (chunk_size + 128KB) align 4KB 大小的空间作为初始的 heap。若已经初始化过了，主分配区则调用 sbrk() 增加 heap 空间，非主分配区则在 top chunk 中切割出一个 chunk，使之满足分配需求，并将指针返回给用户。

- **__libc_malloc (size_t bytes)**

	(malloc.c # 2912)

1. 调用 `arena_get` 获取分配区，得到 `mstate` 指针。

2. 用 arena 指针和请求大小作为参数调用 `_int_malloc`。

3. 给分配区解锁。

4. 在返回 chunk 指针前，以下三者其中之一成立：

	- 返回的指针为空
	- 该 chunk 属于 mmap。
	- 该 chunk 的 arena 是第一步获得的 arena。

## free

- **void _int_free (mstate av, mchunkptr p, int have_lock)**

	(malloc.c # 3870)

	free 函数同样首先要获取分配取得锁，来保证线程安全。

1. 查看内存中 `p` 是否在 `p + chunksize(p)` 之前，否则抛出 ("free(): invalid pointer") 异常。（未理解源码）

2. 查看是否 chunk 的大小至少为 `MINSIZE` 或者 `MALLOC_ALIGNMENT ` 的倍数，否则抛出 ("free(): invalid size") 异常。

3. 如果 chunk 的大小属于 fastbin 范围（并且它的下一个 chunk 不为 top chunk）：

	```
        i. 查看下一个 chunk 的大小是否在最小值和最大值 (av->system_mem) 之间，否则抛出("free(): invalid next size
         (fast)") 异常。

       ii. 调用 free_perturb 将 chunk 的用户数据部分设置成 perturb_byte，标志为已释放的内存。

      iii. 为 `av` 设置 FASTCHUNKS_BIT 值。

      iv. 根据 chunk size 获取对应 fastbin 数组的索引。

       v. 检查 fastbin 头部的 chunk 是否为当前 chunk，如果是则抛出 ("double free or corruption (fasttop)") 异常。

      vi. 检查 fastbin 头部的 chunk 大小是否跟当前 chunk 大小一致。否则抛出 ("invalid fastbin entry (free)") 异常。

     vii. 将该 chunk 插入到 fastbin 链表表头并返回。
	```

4. 如果该 chunk 不是由 mmap 分配的：

	```
        i. 如果还没有获得当前分配区的锁，则获取分配区的锁。

       ii. 查看当前 chunk 是否为 top chunk，如果是则抛出 ("double free or corruption (top)) 异常。

      iii. 查看当前 chunk 是否超出了 arena 的范围，如果是则抛出 (" double free or corruption (out)") 异常。

      iv. 查看 nextchunk 的 PREV_INUSE 标志是否设置，如果未设置则抛出 ("double free or corruption (!prev)") 异常。

       v. 查看 nextchunk 的大小是否在最小值和最大值 (av->system_mem) 之间，否则抛出 ("free(): invalid next size (normal)") 异常。

      vi. 调用 free_perturb 将 chunk 标志为已释放的内存。

     vii. 如果当前 chunk 的 PREV_INUSE 标志设置为空，调用 unlink 移除上一个 chunk。

    viii. 如果 nextchunk 不是 top chunk：
    		i. 如果 nextchunk 是空闲的，则对 nextchunk 调用 unlink，否则清除 nextchunk 的 PREV_INUSE 标志位。
    	       ii. 检查 unsorted bin 头部的 chunk 的 bk 是否等于 unsorted bin (unsorted_chunks(av)->fd->bk
    	       	!= unsorted_chunks(av))，否则抛出 (free(): corrupted unsorted chunks") 异常。
    	      iii. 将合并后的 chunk 插入到 unsorted bin 的头部，如果合并后的 chunk 大小不属于 smallbin 的范围则清除
    	      	fd_nextsize、bk_nextsize。

      ix. 如果 next chunk 是 top chunk，与其合并成为新的 top chunk。

       x. 如果合并后的 chunk 大小大于 FASTBIN 合并的阈值（64KB）：
       		i. 如果 fastbin 中存在空闲的 chunk，则调用 malloc_consolidate 合并 fastbin 中空闲的 chunk 到
       			unsorted bin 中。
       	       ii. 如果当前分配区为主分配区，并且 top chunk 的大小大于 heap 的收缩阈值，则调用 systrim 函数收缩 heap。
       	      iii. 如果为非主分配区，调用 heap_trim 收缩非主分配区的 sub_heap。
       	     iiii. 如果获得分配区的锁，则对分配区解锁。
	```

5. 如果该 chunk 是由 mmap 分配的，则调用 `munmap_chunk` 释放内存。

- **__libc_free (void *mem)**

	(malloc.c # 2944)

1. 如果存在 free 的 hook 函数，则执行该 hook 函数返回。（可以通过写 __free_hook getshell）

2. 如果 `mem` 为0直接返回，然后根据内存指针获取 chunk 指针。

3. 如果当前 free 的 chunk 是通过 mmap() 分配的，调用 munmap_chunk() unmap 本 chunk。munmap_chunk() 函数调用 munmap() 函数释放 mmap() 分配的内存快。同时查看是否 mmap/brk 动态分配阈值需要调整，如果当前 free 的 chunk 的大于设置的 mmap 分配阈值，小于 mmap 分配阈值的最大值，将当前 chunk 的大小赋值给 mmap 分配阈值，并修改 mmap 收缩阈值为 mmap 分配阈值的 2 倍。默认情况下 mmap 分配阈值与 mmap 收缩阈值相等，都为 128KB 。

4. 根据 chunk 指针获取对应 arena 指针。

5. 调用 `_int_free`。

# 0x04 Reference

本文以参考资料为主加上一点自己的理解，仅将本文作为自己的学习笔记参照，要深刻理解 glibc heap 务必要阅读 malloc.c 源码。

- [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/)
- [https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
- [《glibc内存管理ptmalloc源代码分析》](https://paper.seebug.org/papers/Archive/refs/heap/glibc%e5%86%85%e5%ad%98%e7%ae%a1%e7%90%86ptmalloc%e6%ba%90%e4%bb%a3%e7%a0%81%e5%88%86%e6%9e%90.pdf)
- [PWN之堆内存管理](https://paper.seebug.org/255/)
- [Linux堆内存管理深入分析(上)-阿里聚安全](https://jaq.alibaba.com/community/art/show?articleid=315)