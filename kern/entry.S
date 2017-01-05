/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>

# Shift Right Logical 
#define SRL(val, shamt)		(((val) >> (shamt)) & ~(-1 << (32 - (shamt))))


###################################################################
# The kernel (this code) is linked at address ~(KERNBASE + 1 Meg), 
# but the bootloader loads it at address ~1 Meg.
#	
# RELOC(x) maps a symbol x from its link address to its actual
# location in physical memory (its load address).	 
###################################################################

#define	RELOC(x) ((x) - KERNBASE)

#define MULTIBOOT_HEADER_MAGIC (0x1BADB002)
#define MULTIBOOT_HEADER_FLAGS (0)
#define CHECKSUM (-(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS))

###################################################################
# entry point
###################################################################

.text

# The Multiboot header
.align 4
.long MULTIBOOT_HEADER_MAGIC
.long MULTIBOOT_HEADER_FLAGS
.long CHECKSUM

# '_start' specifies the ELF entry point.  Since we haven't set up
# virtual memory when the bootloader enters this code, we need the
# bootloader to jump to the *physical* address of the entry point.
.globl		_start
_start = RELOC(entry)

.globl entry
entry:
    #内核的第一条指令
	movw	$0x1234,0x472			# warm boot

	# We haven't set up virtual memory yet, so we're running from
	# the physical address the boot loader loaded the kernel at: 1MB
	# (plus a few bytes).  However, the C code is linked to run at
	# KERNBASE+1MB.  Hence, we set up a trivial page directory that
	# translates virtual addresses [KERNBASE, KERNBASE+4MB) to
	# physical addresses [0, 4MB).  This 4MB region will be
	# sufficient until we set up our real page table in mem_init
	# in lab 2.

	# Load the physical address of entry_pgdir into cr3.  entry_pgdir
	# is defined in entrypgdir.c.

    # 控制寄存器cr2和cr3是和分页机制相关的寄存器
    # 把entry_pgdir这个页表的起始物理地址送给%eax
    # RELOC宏的功能是计算输入参数的物理地址
	movl	$(RELOC(entry_pgdir)), %eax
	movl	%eax, %cr3

	# Turn on paging.
    # 把cr0的PE位，PG位, WP位都置位1
    # PE位是启用保护标识位，置1，代表运行在保护模式下
    # PG位是分页标识位，置1，代表开启了分页机制
    # WP位是写保护标识，置1，处理器会禁止超级用户程序向用户级只读页面执行写操作
	movl	%cr0, %eax
	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax
	movl	%eax, %cr0

	# Now paging is enabled, but we're still running at a low EIP
	# (why is this okay?).  Jump up above KERNBASE before entering
	# C code.
    # 开始工作在分页机制模式下
    # 接下来的指令就可以跳转[0xf0000000-0xf0400000]范围的指令
    # 把当前运行程序的地址空间提高到[0xf0000000-0xf0400000]范围
	mov	$relocated, %eax
	jmp	*%eax

relocated:

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
    //设置内核堆栈
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer
    # 堆栈向下生长，堆栈指针指向最高地址
    # 最高地址就是bootstacktop的值，所以将这个值赋给堆栈指针寄存器
	movl	$(bootstacktop),%esp #bootstacktop的值：f0110000

    //内核的堆栈设置完成
	# now to C code
	call	i386_init

	# Should never get here, but in case we do, just spin.
spin:	jmp	spin


#启动时的boot stack定义
.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment
	.globl		bootstack

# 在数据段中定义栈顶bootstacktop之前，首先分配了KSTKSIZE的存储空间，专门用于堆栈
# KSTKSIZE = 8 * PGSIZE  = 8 * 4096 = 32KB，所以堆栈的地址空间为 0xf0108000-0xf0110000
bootstack:
	.space		KSTKSIZE
	.globl		bootstacktop   
bootstacktop:

