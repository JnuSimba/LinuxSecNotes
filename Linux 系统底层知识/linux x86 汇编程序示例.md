## 求一组数的最大值的汇编程序
``` asm
#PURPOSE: This program finds the maximum number of a
#	  set of data items.
#
#VARIABLES: The registers have the following uses:
#
# %edi - Holds the index of the data item being examined
# %ebx - Largest data item found
# %eax - Current data item
#
# The following memory locations are used:
#
# data_items - contains the item data. A 0 is used
# to terminate the data
#
 .section .data
data_items: 		#These are the data items
 .long 3,67,34,222,45,75,54,34,44,33,22,11,66,0

 .section .text
 .globl _start
_start:
 movl $0, %edi  	# move 0 into the index register
 movl data_items(,%edi,4), %eax # load the first byte of data
 movl %eax, %ebx 	# since this is the first item, %eax is
			# the biggest

start_loop: 		# start loop
 cmpl $0, %eax  	# check to see if we've hit the end
 je loop_exit
 incl %edi 		# load next value
 movl data_items(,%edi,4), %eax
 cmpl %ebx, %eax 	# compare values
 jle start_loop 	# jump to loop beginning if the new
 			# one isn't bigger
 movl %eax, %ebx 	# move the value as the largest
 jmp start_loop 	# jump to loop beginning

loop_exit:
 # %ebx is the status code for the _exit system call
 # and it already has the maximum number
 movl $1, %eax  	#1 is the _exit() syscall
 int $0x80
```

汇编、链接、运行：  
```
$ as max.s -o max.o
$ ld max.o -o max
$ ./max
$ echo $?
```
这个程序在一组数中找到一个最大的数，并把它作为程序的退出状态。这组数在.data段给出：  
```
data_items:
 .long 3,67,34,222,45,75,54,34,44,33,22,11,66,0
```
.long指示声明一组数，每个数占32位，相当于C语言中的数组。这个数组开头定义了一个符号data_items，汇编器会把数组的首地址作为data_items符号所代表的地址，data_items类似于C语言中的数组名。data_items这个标号没有用.globl声明，因为它只在这个汇编程序内部使用，链接器不需要用到这个名字。除了.long之外，常用的数据声明还有：  

.byte，也是声明一组数，每个数占8位  

.ascii，例如`.ascii "Hello world"`，声明11个数，取值为相应字符的ASCII码。注意，和C语言不同，这样声明的字符串末尾是没有'\0'字符的，如果需要以'\0'结尾可以声明为`.ascii "Hello world\0"`。  

data_items数组的最后一个数是0，我们在一个循环中依次比较每个数，碰到0的时候让循环终止。在这个循环中：  

edi寄存器保存数组中的当前位置，每次比较完一个数就把edi的值加1，指向数组中的下一个数。  

ebx寄存器保存到目前为止找到的最大值，如果发现有更大的数就更新ebx的值。  

eax寄存器保存当前要比较的数，每次更新edi之后，就把下一个数读到eax中。  
```
_start:
 movl $0, %edi
```
初始化edi，指向数组的第0个元素。  

 `movl data_items(,%edi,4), %eax`  
这条指令把数组的第0个元素传送到eax寄存器中。data_items是数组的首地址，edi的值是数组的下标，4表示数组的每个元素占4字节，那么数组中第edi个元素的地址应该是data_items + edi * 4，写在指令中就是data_items(,%edi,4)。  

 `movl %eax, %ebx`  
ebx的初始值也是数组的第0个元素。下面我们进入一个循环，循环的开头定义一个符号start_loop，循环的末尾之后定义一个符号loop_exit。  
```
start_loop:
 cmpl $0, %eax
 je loop_exit
```
比较eax的值是不是0，如果是0就说明到达数组末尾了，就要跳出循环。cmpl指令将两个操作数相减，但计算结果并不保存，只是根据计算结果改变eflags寄存器中的标志位。如果两个操作数相等，则计算结果为0，eflags中的ZF位置1。je是一个条件跳转指令，它检查eflags中的ZF位，ZF位为1则发生跳转，ZF位为0则不跳转，继续执行下一条指令。可见比较指令和条件跳转指令是配合使用的，前者改变标志位，后者根据标志位决定是否跳转。je可以理解成`“jump if equal”`，如果参与比较的两数相等则跳转。  
```
 incl %edi
 movl data_items(,%edi,4), %eax
```
将edi的值加1，把数组中的下一个数传送到eax寄存器中。  
```
 cmpl %ebx, %eax
 jle start_loop
```
把当前数组元素eax和目前为止找到的最大值ebx做比较，如果前者小于等于后者，则最大值没有变，跳转到循环开头比较下一个数，否则继续执行下一条指令。jle表示“jump if less than or equal”。  
```
 movl %eax, %ebx
 jmp start_loop
```
更新了最大值ebx然后跳转到循环开头比较下一个数。jmp是一个无条件跳转指令，什么条件也不判断，直接跳转。loop_exit符号后面的指令调_exit系统调用退出程序。  