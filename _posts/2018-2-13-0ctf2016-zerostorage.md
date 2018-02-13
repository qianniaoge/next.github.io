---
title: 0ctf2016 zerostorage
categories:
  - pwn
tags: unsorted_bin_attack fastbin_attack
published: true
---

# Introduction

知识点：

[unsorted_bin_attack](https://github.com/shellphish/how2heap/blob/master/unsorted_bin_attack.c)


**[zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6)**

./zerostorage: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter
/lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=93c36d63b011f873b2ba65c8562c972ffbea10d9,
 stripped

{% highlight bash %}

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

{% endhighlight %}

这题花了很长时间来做，有种被坑了的感觉，但是也加深了对 glibc 的理解，磕磕绊绊终于利用成功。

程序逻辑相对简单，增删改查多一个 merge，而 merge 函数没有检查合成的两块内存是否为同一块，合成一块后在内存中
将其 free 掉，而用户还可以使用这块内存，造成了 uaf。

我首先尝试了 unsorted bin attack 改 global_max_fast 之后用 fastbin attack 覆盖 realloc_hook，程序限制分配大小
在 0x80 字节到 0x1000 字节之间，则只能 malloc 大小为 libc 地址前两个字节的 chunk，该大小至少为 0x7f00 字节以上
，而 libc 可读写内存页只有 0x6000 (24kb) 字节大小，尝试失败。

由于对 glibc 的理解不够细节，构造这些操作的 payload 已经花去了很长时间，期间多次重温 malloc 源码，重拾之前分析
时有些遗忘的部分和这次出现问题处之前没有注意的部分。在发现内存页大小不够而又耗费了较长时间的情况下，我决定查
看其它表哥的 writeup 学习一波，然而这是这次遇到的坑，看了 writeup 发现表哥们的 exp 是针对 ubuntu 14.04 的，
其中一种利用方式利用了当时的 pie 实现的程序代码段基址和 libc 基址之间的偏移是固定的，写 .bss 段实现任意地址写
，第二种方式现在依然可以利用不过得针对 ubuntu 14.04 的 libc（ ubuntu 14.04 上 tls_dtor_list 的地址在 mmap 区
段，而 ubuntu 16.04 上 tls_dtor_list 在 libc 区段，其上方没有找到合适的值用于 fastbin attack）。想要在 ubuntu 
16.04 上利用成功只能自己上了，又翻到另外一篇 writeup 可能是 libc 的原因，其 realloc_hook 上方有合适的大小可以
用来 fastbin attack，于是我在 ubuntu 16.04 上的 libc 继续往 realloc_hook 上面找，最终发现一处可用的内存。

# Leak Libc

利用程序的 uaf 可以获取到 unsorted bin 地址，根据偏移计算出 libc 基址。

```
insert(p8(0)*0x8)
insert(p8(0)*0x8)
merge(0, 0)
view(2)
```

# Fastbin Attack

实施 fastbin attack 的构造需要在改写 global_max_fast 之前完成，存放 fastbin、small/large bin、unsorted bin 地
址的 main_arena 变量大小为 0x890 字节，而小于 0x112f 的 chunk 释放过程中会引起 main_arena 中原有地址无法通过
fastbin 大小的检查，这样的话构造起来会比较不方便。

我找到的 fastbin attack 的目标为 `__x86_data_cache_size` 和 `__x86_data_cache_size_half` 变量，存放 cpu 一级缓存
 l1d 缓存的大小，由于技术原因 cpu 的一级缓存不像二三级缓存或更高级缓存，其大小被限制在较小的范围内，我的 cpu
 的 l1d 大小是 `16k`，也就是 `0x4000` 字节，符合要求。

总共需要合成三块 0x3ff0 大小的内存，一块用于 free，剩下两块用于 malloc。
```
insert(p8(0)*0x1000)
insert(p8(0)*0x10)  # 准备一个用于改写 fd 值的 note
merge(6, 6)
insert(p8(0)*0x1000)
merge(5, 6)
insert(p8(0)*0x1000)
merge(5, 8)
insert(p8(0)*0xff0)
merge(5, 6)         # 这一块用于 free 的先合成好
```

两块用于调用 malloc 的每个分为两部分，每部分加上隔层，以免 consolidate 在一块。

```
insert(p8(0)*0x1000)
insert(p8(0)*0x10)

insert(p8(0)*0x1000)
insert(p8(0)*0x1000)
merge(9, 10)

insert(p8(0)*0x1000)
insert(p8(0)*0x10)

insert(p8(0)*0x1000)
insert(p8(0)*0xff0)
merge(12, 13)

...
```

## Unsorted Bin Attack

准备好要用的 chunk 后就把 global_max_fast 覆盖成更大的值。

```
delete(4)

payload = p64(unsorted_bin_addr)
payload += p64(libc_base+global_max_fast_off-0x10)
update(2, payload)

insert(p8(0)*0x10)
```

然后就可以实施 fastbin attak 改写 realloc_hook 为 system 地址 getshell，具体细节在
 [exp.py](https://github.com/0x3f97/pwn/blob/master/0ctf2016-zerostorage/exp12.py)。

这其中的难点在于内存破坏范围太大，就需要把内存中需要的变量重新填好，要花费一番功夫来查找需要的变量和计算
它们的偏移。这个利用方式的关键在于内存中是否有合适的值，而 `__x86_data_cache_size` 会由于机器不同而大小不同，
我对一台远程 ubuntu server 也可利用成功，其 cpu 的 l1d 大小为 `32kb`, size_half 也就是 16k，调整一下偏移即可
由于一级缓存的大小限制，这个变量的值如果比较固定的话，可以使这种利用方式相对稳定，更为详细还有待对 cpu cache 
size 进行研究。
