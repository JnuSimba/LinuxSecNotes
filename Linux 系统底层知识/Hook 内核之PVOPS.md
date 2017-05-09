CSysSec注： 本文来自Diting0x的个人博客，讲述在虚拟化平台下如何利用PVOPS框架来hook内核  
转载本文请务必注明，文章出处：《[Hook内核之PVOPS](http://www.csyssec.org/20170301/pvops/)》与作者信息：Diting0x   

pvops是做什么的？ 简单地说，hook kernel.  
利用pvops你可以自定义自己的write_cr3函数，你可以修改页表，追踪页表更新的信息，而这些听起来非常底层的操作，利用pvops都变得简单起来。  

pvops接口来源于Xen项目，初衷是建立一个类虚拟化(para-virtualized）内核来适应于不同的hypervisor，当然也包括适应于非虚拟化平台。  

pvops将类虚拟化操作分成一系列结构：`pv_time_ops`,`pv_cpu_ops`,`pv_mmu_ops`,`pv_lock_ops`和`pv_irq_ops`。  

举个例子，x86系统中利用`MOV CR3` 指令来加载页表。pvops将其替换为一个间接跳转到 `pv_mmu_ops -> write_cr3`函数。 每种虚拟化系统，包括本地x86平台，对这些函数都有自己的实现。 对于x86平台，这些函数的实现只是简单地对原始函数指令的封装。比如对于`pv_mmu_ops -> write_cr3` 函数，x86平台的具体实现为`native_write_cr3` 函数：  
``` c
static inline void native_write_cr3(unsigned long val)
{
        asm volatile("mov %0,%%cr3": : "r" (val), "m" (__force_order));
}
```
pvops将本地底层的硬件指令通过pv_xxx_ops结构体替换为间接跳转函数。下面以`pv_mmu_ops`为例，详细分析其内部结构，`pv_mmu_ops`的定义为：(文中列出主要部分，完整定义，可参看[pv_mmu_ops](http://lxr.free-electrons.com/source/arch/x86/kernel/paravirt.c#L395)  结构定义）  

``` c
struct pv_mmu_ops {
         unsigned long (*read_cr2)(void);
         void (*write_cr2)(unsigned long);
 
         unsigned long (*read_cr3)(void);
         void (*write_cr3)(unsigned long);
 
         /*
          * Hooks for intercepting the creation/use/destruction of an
          * mm_struct.
          */
         void (*activate_mm)(struct mm_struct *prev,
                             struct mm_struct *next);
         void (*dup_mmap)(struct mm_struct *oldmm,
                          struct mm_struct *mm);
         void (*exit_mmap)(struct mm_struct *mm);
 
 
         /* TLB operations */
         void (*flush_tlb_user)(void);
         void (*flush_tlb_kernel)(void);
         void (*flush_tlb_single)(unsigned long addr);
         void (*flush_tlb_others)(const struct cpumask *cpus,
                                  struct mm_struct *mm,
                                  unsigned long start,
                                  unsigned long end);
 
         /* Hooks for allocating and freeing a pagetable top-level */
         int  (*pgd_alloc)(struct mm_struct *mm);
         void (*pgd_free)(struct mm_struct *mm, pgd_t *pgd);
 
         /*
          * Hooks for allocating/releasing pagetable pages when they're
          * attached to a pagetable
          */
         void (*alloc_pte)(struct mm_struct *mm, unsigned long pfn);
         void (*alloc_pmd)(struct mm_struct *mm, unsigned long pfn);
         void (*alloc_pud)(struct mm_struct *mm, unsigned long pfn);
         void (*release_pte)(unsigned long pfn);
         void (*release_pmd)(unsigned long pfn);
         void (*release_pud)(unsigned long pfn);
 
         /* Pagetable manipulation functions */
         void (*set_pte)(pte_t *ptep, pte_t pteval);
         void (*set_pte_at)(struct mm_struct *mm, unsigned long addr,
                            pte_t *ptep, pte_t pteval);
         void (*set_pmd)(pmd_t *pmdp, pmd_t pmdval);
         void (*set_pmd_at)(struct mm_struct *mm, unsigned long addr,
                            pmd_t *pmdp, pmd_t pmdval);
         void (*pte_update)(struct mm_struct *mm, unsigned long addr,
                            pte_t *ptep);
 
}
```
比如说你要在分配页表项的时候hook (`write_cr3`)函数, 可以将(`write_cr3`)函数赋值为自己的自定义函数。 默认情况下，内核中pvops框架中提供的自定义函数如下： (完整可参看 [pv_mmu_ops](http://lxr.free-electrons.com/source/arch/x86/kernel/paravirt.c#L395) 函数定义)   

``` c
struct pv_mmu_ops pv_mmu_ops {
.read_cr2 = native_read_cr2,
.write_cr2 = native_write_cr2,
.read_cr3 = native_read_cr3,
.write_cr3 = native_write_cr3,
 .alloc_pte = paravirt_nop,
.alloc_pmd = paravirt_nop,
.alloc_pud = paravirt_nop,
.release_pte = paravirt_nop,
.release_pmd = paravirt_nop,
.release_pud = paravirt_nop,
.set_pte = native_set_pte,
.set_pte_at = native_set_pte_at,
.set_pmd = native_set_pmd,
.set_pmd_at = native_set_pmd_at,
.pte_update = paravirt_nop,
}
```
接着定义的函数会被传入到这里：  

``` c
 static inline void write_cr3(struct mm_struct *mm, unsigned long pfn)
 {
         PVOP_VCALL2(pv_mmu_ops.write_cr3, mm, pfn);
}
```
至于`PVOP_VCALL2` 具体做了什么，可以不必去关心。  