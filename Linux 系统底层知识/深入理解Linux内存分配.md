CSysSec注： 本文来自Diting0x的个人博客，主要介绍了Linux内核中一系列的内存分配函数及其原理  
转载本文请务必注明，文章出处：《[深入理解Linux内核分配](http://www.csyssec.org/20170301/kernel-malloc/)》与作者信息：Diting0x  

为了写一个用户层程序，你也许会声明一个全局变量，这个全局变量可能是一个int类型也可能是一个数组，而声明之后你有可能会先初始化它，也有可能放在之后用到它的时候再初始化。除此之外，你有可能会选择在函数内部去声明局部变量，又或者为变量动态申请内存。  

不管你在用户程序中采取哪种方式申请内存，这些都对应着不同的内存分配方式以及不同的数据段，如果再加上代码段，就构成了一个完整的进程。由此可见，一个完整的进程在内存空间中对应着不同的数据区，具体来说，对应着五种不同的数据区：  

代码段,存放操作指令；数据段,存放已初始化的全局变量；BSS段,存放未初始化的全局变量；堆,存放动态分配的内存(e.g.,malloc())；栈,存放临时创建的局部变量。  

当你习惯写用户程序时，你不会去太多考虑你声明的变量最后都放到内存哪里去了，如果你仍然觉得这不是你应该了解的事情，后面的内容你就可以不用浪费时间继续阅读了。下文更多的是关注内核空间的分配，但至少也会把用户空间的分配情况说清楚。  

对于x86系统来说，4G的内存空间被分为用户空间(e.g.,0-3G,0xC0000000)与内核空间(e.g.,3G-4G)，用户程序只能在进行系统调用时才能访问到内核空间。此外，当进程切换时，用户空间会随着进程的变化切换到对应进程的用户空间，而内核空间不会随着进程而改变，由内核负责映射。内核空间有自己对应的页表，而用户进程各自有不同的页表。  

从用户层向内核看，内存的地址形式依次是，逻辑地址--线性地址--物理地址，但Linux并没有充分利用段机制，而是将所有程序的段地址固定在0-4G,因此逻辑地址就等于线性地址。  

了解这些基本知识之后，来看看进程的虚拟地址是如何组织的。  
一个进程的虚拟地址空间主要由两个数据结构来描述，mm_struct与vm_area_struct。 来具体说说这两个结构体用来做什么  

每个进程有一个mm_struct结构，在进程的task_struct结构体中有一个指针指向mm_struct。 mm_struct的定义如下：  

``` c
struct mm_struct {
         struct vm_area_struct * mmap;           /* 指向虚拟区间（VMA）链表 */
         rb_root_t mm_rb;         ／*指向red_black树*/
         struct vm_area_struct * mmap_cache;     /* 指向最近找到的虚拟区间*/
         pgd_t * pgd;             ／*指向进程的页目录*/
              atomic_t mm_users;                   /* 用户空间中的有多少用户*/                                     
              atomic_t mm_count;               /* 对"struct mm_struct"有多少引用*/                                     
         int map_count;                        /* 虚拟区间的个数*/
         struct rw_semaphore mmap_sem;
      spinlock_t page_table_lock;        /* 保护任务页表和 mm->rss */                                              
         struct list_head mmlist;            /*所有活动（active）mm的链表 */
         unsigned long start_code, end_code, start_data, end_data;
         unsigned long start_brk, brk, start_stack;
         unsigned long arg_start, arg_end, env_start, env_end;
         unsigned long rss, total_vm, locked_vm;
         unsigned long def_flags;
         unsigned long cpu_vm_mask;
         unsigned long swap_address;
 
         unsigned dumpable:1;
 
         /* Architecture-specific MM context */
         mm_context_t context;
};
```
简单来说，mm_struct是对整个进程的用户空间的描述，而进程的虚拟空间可能有多个虚拟区间(这里的区间就是由vm_area_struct来描述). vm_area_struct是描述进程虚拟空间的基本单元，那这些基本单元又是如何管理组织的呢？内核采取两种方式来组织这些基本单元，第一，正如mm_struct中的mmap指针指向vm_area_struct，以链表形式存储，这种结构主要用来遍历节点；第二，以红黑树来组织vm_area_struct，这种结构主要在定位特定内存区域时用来搜索，以降低耗时。  

了解了这些关联之后，回到最前面，当你写的用户程序在申请内存时(e.g., int i =0; malloc())，注意这里申请的内存还是虚拟内存，可以说是“内存区域”(vm_area_struct)，并非实际物理内存。 这些虚拟内存除了malloc()方式(由专门的brk()系统调用实现)，最终都是通过系统调用mmap来完成的，而mmap系统调用对应的服务例程是do_mmap()函数，有关do_mmap()函数，可参考[do_mmap()](http://lxr.free-electrons.com/source/mm/mmap.c?v=2.6.25#L1843).  

说了这么多用户空间，该把重心来看看内核空间了。  
用户空间有malloc内存分配函数，内核空间同样有类似的内存分配函数，只是种类多一些(e.g.,*kmalloc/kfree,vmalloc/vfree,kmem_cache_alloc/kmem_cache_free,get_free_page).  
在具体解释内核空间层的内存分配函数之前，先来看看，物理内存是如何组织的。Linux通过分页机制来管理物理内存，页面是物理内存的基本单位，每个页面占4kB。页面在系统中由struct page结构来描述，而所有的struct page结构体都存储在数组mem_map[]中，因此只要能找到mem_map[]数组的物理地址，就能遍历所有页面的地址。可以来大致看一下struct page*的定义：  

``` c
struct page {
         unsigned long flags;                                                      
         atomic_t count;                
         unsigned int mapcount;          
         unsigned long private;          
         struct address_space *mapping;  
         pgoff_t index;                  
         struct list_head lru;  
     union{
        struct pte_chain;
        pte_addr_t;
     }         
         void *virtual;                  
};
```
其中，flag用来存放页的状态，count记录该页面被引用了多少次，mapping指向该页面相关的地址空间对象… 这里只是一个简化的定义，真实情况会复杂一些，要把page说清楚，需要写一篇新的博客了，之后的文章会专门介绍。需要注意的是，page描述的是物理内存本身，而并非包含在里面的数据。  

那这些page又和内核空间的内存分配有什么关系呢？  
内核空间有一系列的页面分配函数：  

``` c
struct page * alloc_page(unsigned int gfp_mask)
//Allocate a single page and return a struct address
 
struct page * alloc_pages(unsigned int gfp_mask, unsigned int order)
//Allocate 2order number of pages and returns a struct page
 
unsigned long get_free_page(unsigned int gfp_mask)
//Allocate a single page, zero it and return a virtual address
 
unsigned long __get_free_page(unsigned int gfp_mask)
//Allocate a single page and return a virtual address
 
unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
//Allocate 2order number of pages and return a virtual address
 
struct page * __get_dma_pages(unsigned int gfp_mask, unsigned int order)
//Allocate 2order number of pages from the DMA zone and return a struct page
```
以 `__get_free_pages` 为例看看其函数间调用关系：  

``` c
unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
 {
         page = alloc_pages(gfp_mask, order);
 }
```

`#define alloc_pages(gfp_mask, order) \              alloc_pages_node(numa_node_id(), gfp_mask, order)`

``` c
static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,unsigned int order)
 {
         return __alloc_pages_node(nid, gfp_mask, order);
}
```
``` c
static inline struct page * __alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
 {
  
       return __alloc_pages(gfp_mask, order, node_zonelist(nid, gfp_mask));
 }
```
最终 `__get_free_page` 会调用 `__alloc_pages` 函数分配页面。`__alloc_pages` 是所有页面分配函数的核心函数，最终都会调用到这个函数，它会返回一个struct page结构。  

在了解与其它内存分配函数的区别前，先说明下面这个概念  

前文说过3G-4G属于内核空间，然后在内核空间中又有进一步划分。  
3G~vmalloc_start这段地址是物理内存映射区域，该区域包括了内核镜像，mem_map数组等等。在vmalloc_start~vmalloc_end属于vmalloc区域（vmalloc下文会说),vmalloc_end的位置接近4G(最后系统会保留一片128KB大小的区域专用页面映射). 那这个vmalloc_start的位置又在哪呢？假设我们使用的系统内存是512M,vmalloc_start就在应在3G+512M附近（说”附近”因为是在物理内存映射区与vmalloc_start期间还会存在一个8M大小的gap来防止跃界）.当然实际情况都比这个大，甚至都4G，8G，16G..但我们使用的CPU都是64位的，可寻址空间就不止4G了，这个理论仍然有效。  

`__get_free_page` 系列函数申请的内存位于物理内存映射区域，在物理上是连续的，注意，函数返回的是虚拟地址，其与物理地址有一个固定的偏移，存在比较简单的转换关系，virt_to_phys()函数做的就是这件事：  

``` c
#define __pa(x) ((unsigned long)(x)-PAGE_OFFSET)
 extern inline unsigned long virt_to_phys(volatile void * address)
 {
     　return __pa(address);
 }
``` 
注意，这里的PAGE_OFFSET指的就是3G(针对x86位系统).  

与页面分配系函数一样，kmalloc函数申请的内存也处于物理内存映射区域，在物理上是连续的。Kmalloc函数是slab分配器提供的分配内存的接口，slab是什么？这里不去具体讲slab分配原理,想详细了解的slab可以参考 [这里](https://www.kernel.org/doc/gorman/html/understand/understand011.html). 简单说明一下：slab是为了避免内部碎片使得一个页面内包含的众多小块内存可独立被分配使用，是为分配小内存提供的一种高效机制。追踪kmalloc函数，可以发现，它最终还是调用前面提到的
`__alloc_pages()`函数。既然kmalloc基于slab实现，而slab分配机制又不是独立的，本身也是在以页面为单位分配的基础上来划分更细粒度的内存供调用者使用。就是说系统先用页分配器分配以页为最小单位的连续物理地 址，然后kmalloc再在这上面根据调用者的需要进行切分。  

既然slab是为了解决内部碎片的问题，那想必也有一个解决外部碎片的机制(注：外部分片是指系统虽有足够的内存，但却是分散的碎片，无法满足对大块“连续内存”的需求)。没错，伙伴关系系统就是这么一个机制。伙伴关系系统提供vmalloc来分配非连续内存,其分配的地址限于上述说的vmalloc_start~vmalloc_end之间。这些虚拟地址与物理内存没有简单的位移关系，必须通过内核页表才可转换为物理地址或物理页。它们有可能尚未被映射，在发生缺页时才真正分配物理页面。  

说到这里，还有一个关键函数没提，kmem_cache_alloc。 kmem_cache_alloc也是基于slab分配器的一种内存分配方式，适用于反复分配同一大小内存块的场合。首先用kmem_cache_create创建一个高速缓存区域，然后用kmem_cache_alloc从该高速缓存区域获取新的内存块。`kmem_cache_alloc` 分配固定大小的内存块。kmalloc则是在kmem_cache_create的基础实现的，其分配动态大小的内存块，查看源码可以发现kmalloc函数中会有一段代码块转向调用kmem_cache_alloc：  

``` c
static inline void *kmalloc(size_t size, gfp_t flags)
      {
          if (__builtin_constant_p(size)) {
              int i = 0;
      #define CACHE(x) \
              if (size <= x) \
                  goto found; \
              else \
                  i++;
      #include "kmalloc_sizes.h"
      #undef CACHE
              {
                  extern void __you_cannot_kmalloc_that_much(void);
                  __you_cannot_kmalloc_that_much();
              }
      found:
              return kmem_cache_alloc((flags & GFP_DMA) ?
                  malloc_sizes[i].cs_dmacachep :
                  malloc_sizes[i].cs_cachep, flags);
          }
          return __kmalloc(size, flags);
     }
```
内核空间常用的内存分配函数就此说完了，实际除了这些常用的，还有其它的分配函数，在此简单说明一下。如，`dma_alloc_coherent`，基于
`__alloc_pages` 实现，适用于DMA操作；ioremap,实现已知物理地址到虚拟地址的映射，适用于物理地址已经的场合，如设备驱动；alloc_bootmem，在启动内核时，预留一段内存，内核看不见，对内存管理要求较高。  