# LinuxSecNotes
此系列文章是本人关于学习 Linux 安全时记录的一些笔记，部分原创，部分是对网上文章的理解整理。如果可以找到原始参考链接时则会在文末贴出（如 乌云很多链接已失效，或者记不起当时存档时的链接），或者在文章开头写上 by xx，如有侵权请联系我（dameng34 at 163.com）删除或加上reference，感谢在网上共享知识的师傅们，觉得内容不错的朋友请不要吝啬您的 **star**。  

欢迎扫描关注我的微信公众号

![appsec](https://raw.githubusercontent.com/JnuSimba/MiscSecNotes/master/pictures/appsec.jpg)

## 文章目录

* Linux 系统底层知识
	- 汇编指令
		- [X86 Assembly Guide](./Linux%20系统底层知识/X86%20Assembly%20Guide.md)
		- [linux x86 汇编程序示例](./Linux%20系统底层知识/linux%20x86%20汇编程序示例.md)
		- [Linux 函数堆栈调用](./Linux%20系统底层知识/Linux%20函数堆栈调用.md)
	- ELF 文件
		- [ELF 文件简介](./Linux%20系统底层知识/ELF%20文件简介.md)
		- [动态延迟绑定原理](./Linux%20系统底层知识/动态延迟绑定原理.md)
		- [理解编译链接的那些事儿](./Linux%20系统底层知识//理解编译链接的那些事儿.md)
	- 系统调用
		- [Linux 系统调用权威指南](./Linux%20系统底层知识/Linux%20系统调用权威指南.md)
		- [Malloc使用的系统调用](./Linux%20系统底层知识/Malloc使用的系统调用.md)
	- 内存管理
		 - [深入理解glibc malloc](./Linux%20系统底层知识/深入理解glibc%20malloc.md)
      	 - [深入理解Linux内存分配](./Linux%20系统底层知识/深入理解Linux内存分配.md)
        	 - [Linux 堆内存管理深入分析（上）](./Linux%20系统底层知识/Linux%20堆内存管理深入分析（上）.md)
          	 - [Linux 堆内存管理深入分析（下）](./Linux%20系统底层知识/Linux%20堆内存管理深入分析（下）.md)
	- exploit 调试
	    - [Linux 栈溢出保护机制](./Linux%20系统底层知识/Linux%20栈溢出保护机制.md)
		- [反调试与反反调试](./Linux%20系统底层知识/反调试与反反调试.md)
	    - [Hook 内核之PVOPS](./Linux%20系统底层知识/Hook%20内核之PVOPS.md)
	    - [Born A Shell](./Linux%20系统底层知识/Born%20A%20Shell.md)
	
* Linux(X86)漏洞利用系列
	- 缓冲区溢出
		- [经典栈缓冲区溢出](./Linux%20X86%20漏洞利用系列/经典栈缓冲区溢出.md)
		- [整型溢出](./Linux%20X86%20漏洞利用系列/整型溢出.md)
		- [栈内off-by-one 漏洞利用](./Linux%20X86%20漏洞利用系列/栈内off-by-one%20漏洞利用.md)
		- [Format String](./Linux%20X86%20漏洞利用系列/Format%20String.md)
		- [缓冲区溢出的前世今生](./Linux%20X86%20漏洞利用系列/缓冲区溢出的前世今生.md)
	- 堆溢出
		- [Unlink堆溢出](./Linux%20X86%20漏洞利用系列/Unlink堆溢出.md)
		- [Double Free 浅析](./Linux%20X86%20漏洞利用系列/Double%20Free%20浅析.md)  
		- [Malloc Maleficarum堆溢出](./Linux%20X86%20漏洞利用系列/Malloc%20Maleficarum堆溢出.md)
			- [THE HOUSE OF PRIME](./Linux%20X86%20漏洞利用系列/THE%20HOUSE%20OF%20PRIME.md)
			- [THE HOUSE OF MIND](./Linux%20X86%20漏洞利用系列/THE%20HOUSE%20OF%20MIND.md)
			- [THE HOUSE OF FORCE](./Linux%20X86%20漏洞利用系列/THE%20HOUSE%20OF%20FORCE.md)
			- [THE HOUSE OF LORE](./Linux%20X86%20漏洞利用系列/THE%20HOUSE%20OF%20LORE.md)
			- [THE HOUSE OF SPIRIT](./Linux%20X86%20漏洞利用系列/THE%20HOUSE%20OF%20SPIRIT.md)
		- [堆内off-by-one漏洞利用](./Linux%20X86%20漏洞利用系列/堆内off-by-one漏洞利用.md)
		- [user-after-free](./Linux%20X86%20漏洞利用系列/user-after-free.md)
	- 绕过漏洞缓解
		- [return-to-libc 绕过NX](./Linux%20X86%20漏洞利用系列/return-to-libc%20绕过NX.md)
		- [Return-to-libc链接绕过NX](./Linux%20X86%20漏洞利用系列/Return-to-libc链接绕过NX.md)
		- [return-to-dl-resolve](./Linux%20X86%20漏洞利用系列/return-to-dl-resolve.md)
		- [绕过ASLR-第一篇章（return-to-plt）](./Linux%20X86%20漏洞利用系列/绕过ASLR-第一篇章（return-to-plt）.md)
		- [绕过ASLR-第二篇章（暴力破解）](./Linux%20X86%20漏洞利用系列/绕过ASLR-第二篇章（暴力破解）.md)
		- [绕过ASLR-第三篇章（GOT覆盖与GOT解引用）](./Linux%20X86%20漏洞利用系列/绕过ASLR-第三篇章（GOT覆盖与GOT解引用）.md)
	- 一步一步学ROP
		- [Linux x86 篇](./一步一步学ROP/Linux%20x86%20篇.md)
		- [Linux x64 篇](./一步一步学ROP/Linux%20x64%20篇.md)
		- [gadgets和2free篇](./一步一步学ROP/gadgets和2free%20篇.md)
		- [Android ARM 32位篇](./一步一步学ROP/Android%20ARM%2032位篇.md)
	
