## 函数调用堆栈
我们用下面的C代码来研究函数调用的过程。  
``` c
int bar(int c, int d)
{
    int e = c + d;
    return e;
}

int foo(int a, int b)
{
    return bar(a, b);
}

int main(void)
{
    foo(2, 3);
    return 0;
}
```
如果在编译时加上-g选项，那么用objdump反汇编时可以把C代码和汇编代码穿插起来显示，这样C代码和汇编代码的对应关系看得更清楚。反汇编的结果很长，以下只列出我们关心的部分。  
`simba@ubuntu:~/Documents/code/asm$ objdump -dS a.out` 
``` asm
int bar(int c, int d)
{ 
 80483dc:       55                      push   %ebp
 80483dd:       89 e5                   mov    %esp,%ebp
 80483df:       83 ec 10                sub    $0x10,%esp
        int e = c + d; 
 80483e2:       8b 45 0c                mov    0xc(%ebp),%eax
 80483e5:       8b 55 08                mov    0x8(%ebp),%edx
 80483e8:       01 d0                   add    %edx,%eax
 80483ea:       89 45 fc                mov    %eax,-0x4(%ebp)
        return e;
 80483ed:       8b 45 fc                mov    -0x4(%ebp),%eax
}
 80483f0:       c9                      leave  
 80483f1:       c3                      ret    

080483f2 <foo>:

int foo(int a, int b)
{ 
 80483f2:       55                      push   %ebp
 80483f3:       89 e5                   mov    %esp,%ebp
 80483f5:       83 ec 08                sub    $0x8,%esp
        return bar(a, b);
 80483f8:       8b 45 0c                mov    0xc(%ebp),%eax
 80483fb:       89 44 24 04             mov    %eax,0x4(%esp)
 80483ff:       8b 45 08                mov    0x8(%ebp),%eax
 8048402:       89 04 24                mov    %eax,(%esp)
 8048405:       e8 d2 ff ff ff          call   80483dc <bar>
}
 804840a:       c9                      leave  
 804840b:       c3                      ret    

0804840c <main>:

int main(void)
{ 
 804840c:       55                      push   %ebp
 804840d:       89 e5                   mov    %esp,%ebp
 804840f:       83 ec 08                sub    $0x8,%esp
        foo(2, 3); 
 8048412:       c7 44 24 04 03 00 00    movl   $0x3,0x4(%esp)
 8048419:       00 
 804841a:       c7 04 24 02 00 00 00    movl   $0x2,(%esp)
 8048421:       e8 cc ff ff ff          call   80483f2 <foo>
        return 0;
 8048426:       b8 00 00 00 00          mov    $0x0,%eax
}
 804842b:       c9                      leave  
 804842c:       c3                      ret 
```
要查看编译后的汇编代码，其实还有一种办法是gcc -S main.c，这样只生成汇编代码main.s，而不生成二进制的目标文件。  
整个程序的执行过程是main调用foo，foo调用bar，我们用gdb跟踪程序的执行，直到bar函数中的int e = c + d;语句执行完毕准备返回时，这时在gdb中打印函数栈帧，因为此时栈已经生长到最大。  
```
simba@ubuntu:~/Documents/code/asm$ gdb a.out
GNU gdb (GDB) 7.5-ubuntu
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-Linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /home/simba/Documents/code/asm/a.out...done.
(gdb) start
Temporary breakpoint 1 at 0x8048412: file foo_bar.c, line 22.
Starting program: /home/simba/Documents/code/asm/a.out 


Temporary breakpoint 1, main () at foo_bar.c:22
22              foo(2, 3); 
(gdb) s
foo (a=2, b=3) at foo_bar.c:17
17              return bar(a, b);
(gdb) s
bar (c=2, d=3) at foo_bar.c:11
11              int e = c + d; 
(gdb) disas
Dump of assembler code for function bar:
   0x080483dc <+0>:     push   %ebp
   0x080483dd <+1>:     mov    %esp,%ebp
   0x080483df <+3>:     sub    $0x10,%esp
=> 0x080483e2 <+6>:     mov    0xc(%ebp),%eax
   0x080483e5 <+9>:     mov    0x8(%ebp),%edx
   0x080483e8 <+12>:    add    %edx,%eax
   0x080483ea <+14>:    mov    %eax,-0x4(%ebp)
   0x080483ed <+17>:    mov    -0x4(%ebp),%eax
   0x080483f0 <+20>:    leave  
   0x080483f1 <+21>:    ret    
End of assembler dump.
(gdb) si
0x080483e5      11              int e = c + d; 
(gdb) 
0x080483e8      11              int e = c + d; 
(gdb) 
0x080483ea      11              int e = c + d; 
(gdb) 
12              return e;
(gdb) 
13      }
(gdb) bt
#0  bar (c=2, d=3) at foo_bar.c:13
#1  0x0804840a in foo (a=2, b=3) at foo_bar.c:17
#2  0x08048426 in main () at foo_bar.c:22
(gdb) info registers
eax            0x5      5
ecx            0xbffff744       -1073744060
edx            0x2      2
ebx            0xb7fc6000       -1208197120
esp            0xbffff678       0xbffff678
ebp            0xbffff688       0xbffff688
esi            0x0      0
edi            0x0      0
eip            0x80483f0        0x80483f0 <bar+20>
eflags         0x206    [ PF IF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/20x $esp
0xbffff678:     0x0804a000      0x08048482      0x00000001      0x00000005
0xbffff688:     0xbffff698      0x0804840a      0x00000002      0x00000003
0xbffff698:     0xbffff6a8      0x08048426      0x00000002      0x00000003
0xbffff6a8:     0x00000000      0xb7e394d3      0x00000001      0xbffff744
0xbffff6b8:     0xbffff74c      0xb7fdc858      0x00000000      0xbffff71c
```
在执行程序时，操作系统为进程分配一块栈空间来保存函数栈帧，esp寄存器总是指向栈顶，在x86平台上这个栈是从高地址向低地址增长的，我们知道每次调用一个函数都要分配一个栈帧来保存参数和局部变量，现在我们详细分析这些数据在栈空间的布局，根据gdb的输出结果图示如下：  
![](../pictures/linuxstack.jpg)  

图中每个小方格表示4个字节的内存单元，例如b: 3这个小方格占的内存地址是0xbffff6a4~0xbffff6a8，我把地址写在每个小方格的下边界线上，是为了强调该地址是内存单元的起始地址。我们从main函数的这里开始看起：  
``` asm
foo(2, 3); 
 8048412:       c7 44 24 04 03 00 00    movl   $0x3,0x4(%esp)
 8048419:       00 
 804841a:       c7 04 24 02 00 00 00    movl   $0x2,(%esp)
 8048421:       e8 cc ff ff ff          call   80483f2 <foo>
```
要调用函数foo先要把参数准备好，第二个参数保存在esp+4指向的内存位置，第一个参数保存在esp指向的内存位置，可见参数是从右向左依次压栈的。然后执行call指令，这个指令有两个作用：  
1. foo函数调用完之后要返回到call的下一条指令继续执行，所以把call的下一条指令的地址0x8048426压栈，同时把esp的值减4，esp的值现在是0xbffff69c（可以在main函数开始执行时info r 一下，此时esp为0xbffff6a0）。
2. 修改程序计数器eip，跳转到foo函数的开头执行。

现在看foo函数的汇编代码：  
``` asm
int foo(int a, int b)
{ 
 80483f2:       55                      push   %ebp
 80483f3:       89 e5                   mov    %esp,%ebp
 80483f5:       83 ec 08                sub    $0x8,%esp
        return bar(a, b);
 80483f8:       8b 45 0c                mov    0xc(%ebp),%eax
 80483fb:       89 44 24 04             mov    %eax,0x4(%esp)
 80483ff:       8b 45 08                mov    0x8(%ebp),%eax
 8048402:       89 04 24                mov    %eax,(%esp)
 8048405:       e8 d2 ff ff ff          call   80483dc <bar>
}
```
push %ebp指令把ebp寄存器的值压栈，同时把esp的值减4。esp的值现在是0xbffff698，下一条指令把这个值传送给ebp寄存器。这两条指令合起来是把原来ebp的值保存在栈上，然后又给ebp赋了新值。在每个函数的栈帧中，ebp指向栈底，而esp指向栈顶，在函数执行过程中esp随着压栈和出栈操作随时变化，而ebp是不动的，函数的参数和局部变量都是通过ebp的值加上一个偏移量来访问，例如foo函数的参数a和b分别通过ebp+8和ebp+12来访问。所以下面的指令把参数a和b再次压栈，为调用bar函数做准备，然后把返回地址压栈，调用bar函数：  

现在看bar函数的指令：  
``` asm
 
int bar(int c, int d)
{ 
 80483dc:       55                      push   %ebp
 80483dd:       89 e5                   mov    %esp,%ebp
 80483df:       83 ec 10                sub    $0x10,%esp
        int e = c + d; 
 80483e2:       8b 45 0c                mov    0xc(%ebp),%eax
 80483e5:       8b 55 08                mov    0x8(%ebp),%edx
 80483e8:       01 d0                   add    %edx,%eax
 80483ea:       89 45 fc                mov    %eax,-0x4(%ebp)
``` 

这次又把foo函数的ebp压栈保存，然后给ebp赋了新值，指向bar函数栈帧的栈底，通过ebp+8和ebp+12分别可以访问参数c和d。bar函数还有一个局部变量e，可以通过ebp-4来访问。所以后面几条指令的意思是把参数c和d取出来存在寄存器中做加法，计算结果保存在eax寄存器中，再把eax寄存器存回局部变量e的内存单元。  

在gdb中可以用bt命令和frame命令查看每层栈帧上的参数和局部变量，现在可以解释它的工作原理了：如果我当前在bar函数中，我可以通过ebp找到bar函数的参数和局部变量，也可以找到foo函数的ebp保存在栈上的值，有了foo函数的ebp，又可以找到它的参数和局部变量，也可以找到main函数的ebp保存在栈上的值，因此各层函数栈帧通过保存在栈上的ebp的值串起来了。  

现在看bar函数的返回指令：  
``` asm
      return e;
 80483ed:       8b 45 fc                mov    -0x4(%ebp),%eax
}
 80483f0:       c9                      leave  
 80483f1:       c3                      ret    
```
bar函数有一个int型的返回值，这个返回值是通过eax寄存器传递的，所以首先把e的值读到eax寄存器中。  
然后执行leave指令，这个指令是函数开头的push %ebp和mov %esp,%ebp的逆操作：  

1. 把ebp的值赋给esp，现在esp的值是0xbffff688。
2. 现在esp所指向的栈顶保存着foo函数栈帧的ebp，把这个值恢复给ebp，同时esp增加4，esp的值变成0xbffff68c。

最后是ret指令，它是call指令的逆操作：  

1. 现在esp所指向的栈顶保存着返回地址，把这个值恢复给eip（pop），同时esp增加4，esp的值变成0xbffff690。
2. 修改了程序计数器eip，因此跳转到返回地址0x804840a继续执行。

地址0x804840a处是foo函数的返回指令：  
``` asm
 804840a:       c9                      leave  
 804840b:       c3                      ret    
```
重复同样的过程，又返回到了main函数。  
根据上面的分析，ebp最终会重新获取值0x00000000, 而从main函数返回到0xb7e39473地址去执行，最终esp值为0xbffff6b0。  
当main函数最后一条指令执行完是info r 一下可以发现：  
```
esp            0xbffff6b0       0xbffff6b0
ebp            0x0      0x0
```
实际上回过头发现main函数最开始也有初始化的3条汇编指令，先把ebp压栈，此时esp减4为0x6ffffba8，再将esp赋值给ebp，最后将esp减去8，所以在我们调试第一条运行的指令（movl   $0x3,0x4(%esp) ）时，esp已经是0x6ffff6a0，与前面对照发现是吻合的。那么main函数回到哪里去执行呢？实际上main函数也是被其他系统函数所调用的，比如进一步si 下去会发现 是 被 libc-start.c 所调用，最终还会调用exit.c。为了从main函数入口就开始调试，可以设置一个断点如下：  
```
(gdb) disas main
Dump of assembler code for function main:
   0x0804840c <+0>:     push   %ebp
   0x0804840d <+1>:     mov    %esp,%ebp
   0x0804840f <+3>:     sub    $0x8,%esp
   0x08048412 <+6>:     movl   $0x3,0x4(%esp)
   0x0804841a <+14>:    movl   $0x2,(%esp)
   0x08048421 <+21>:    call   0x80483f2 <foo>
   0x08048426 <+26>:    mov    $0x0,%eax
   0x0804842b <+31>:    leave  
   0x0804842c <+32>:    ret    
End of assembler dump.
(gdb) b *0x0804840c
Breakpoint 1 at 0x804840c: file foo_bar.c, line 21.
(gdb) r
Starting program: /home/simba/Documents/code/asm/a.out 


Breakpoint 1, main () at foo_bar.c:21
21      { 
(gdb) i reg
eax            0x1      1
ecx            0xbffff744       -1073744060
edx            0xbffff6d4       -1073744172
ebx            0xb7fc6000       -1208197120
esp            0xbffff6ac       0xbffff6ac
ebp            0x0      0x0
esi            0x0      0
edi            0x0      0
eip            0x804840c        0x804840c <main>
eflags         0x246    [ PF ZF IF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/x $esp
0xbffff6ac:     0xb7e394d3
(gdb) x/10i 0xb7e394d3-10
   0xb7e394c9 <__libc_start_main+233>:  inc    %esp
   0xb7e394ca <__libc_start_main+234>:  and    $0x74,%al
   0xb7e394cc <__libc_start_main+236>:  mov    %eax,(%esp)
   0xb7e394cf <__libc_start_main+239>:  call   *0x70(%esp)
   0xb7e394d3 <__libc_start_main+243>:  mov    %eax,(%esp)
   0xb7e394d6 <__libc_start_main+246>:  call   0xb7e52fb0 <__GI_exit>
   0xb7e394db <__libc_start_main+251>:  xor    %ecx,%ecx
   0xb7e394dd <__libc_start_main+253>:  jmp    0xb7e39414 <__libc_start_main+52>
   0xb7e394e2 <__libc_start_main+258>:  mov    0x3928(%ebx),%eax
   0xb7e394e8 <__libc_start_main+264>:  ror    $0x9,%eax
(gdb) x/x $esp+4+0x70
0xbffff720:     0x0804840c
```
可以看到main函数最开始时,esp为0xbffff6ac，ebp为0，eip为0x804840c，esp所指的0xb7e394d3就是main函数执行完的返回地址，如何证明呢？  
可以看到0xb7e394cf 处的指令 call *0x70(%esp) ，即将下一条地址压栈，打印一下 esp+4+0x70 指向的地址为0x804840c，也就是main函数的入口地址。此外可以看到调用call 时esp 应该为0xbffff6b0，与main 函数执行完毕时的esp 值一致。  

知道了main函数的返回地址，我们也就明白了所谓的shellcode的大概实现原理，利用栈空间变量的缓冲区溢出将返回地址覆盖掉，将esp所指返回地址pop到eip时，就会改变程序的流程，不再是正确地退出，而是被我们所控制了，一般是跳转到一段shellcode（机器指令）的起始地址，这样就启动了一个shell。  

注意函数调用和返回过程中的这些规则：  

1. 参数压栈传递，并且是从右向左依次压栈。
2. ebp总是指向当前栈帧的栈底。
3. 返回值通过eax寄存器传递。

这些规则并不是体系结构所强加的，ebp寄存器并不是必须这么用，函数的参数和返回值也不是必须这么传，只是操作系统和编译器选择了以这样的方式实现C代码中的函数调用，这称为Calling Convention，Calling Convention是操作系统二进制接口规范（ABI，Application Binary Interface）的一部分。  

## 参考
《linux c 编程一站式学习》  
《网络渗透技术》  
