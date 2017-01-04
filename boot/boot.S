#include <inc/mmu.h>

# Start the CPU: switch to 32-bit protected mode, jump into C.
# The BIOS loads this code from the first sector of the hard disk into
# memory at physical address 0x7c00 and starts executing in real mode
# with %cs=0 %ip=7c00.

.set PROT_MODE_CSEG, 0x8         # kernel code segment selector
.set PROT_MODE_DSEG, 0x10        # kernel data segment selector
.set CR0_PE_ON,      0x1         # protected mode enable flag

.globl start
start:
  .code16                     # Assemble for 16-bit mode
  # 第一条指令，关闭所有的中断
  cli                         # Disable interrupts
  cld                         # String operations increment

  # Set up the important data segment registers (DS, ES, SS).
  # 将ds，es，ss全部清零
  xorw    %ax,%ax             # Segment number zero
  movw    %ax,%ds             # -> Data Segment
  movw    %ax,%es             # -> Extra Segment
  movw    %ax,%ss             # -> Stack Segment

  # Enable A20: 使能A20线
  #   For backwards compatibility with the earliest PCs, physical
  #   address line 20 is tied low, so that addresses higher than
  #   1MB wrap around to zero by default.  This code undoes this.
seta20.1:

  #  不断的检测bit1。bit1的值代表输入缓冲区是否满了，CPU传送给控制器的数据，
  #  控制器是否已经取走了，如果CPU想向控制器传送新的数据的话，必须先保证这一
  #  位为0。所以这三条指令会一直等待这一位变为0，才能继续向后运行
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al
  jnz     seta20.1

  # 指令向控制器输入指令，0xd1
  # D1指令代表下一次写入0x60端口的数据将被写入给804x控制器的输出端口
  movb    $0xd1,%al               # 0xd1 -> port 0x64
  outb    %al,$0x64

seta20.2:
  # 指令再次等待，等待刚刚写入的指令D1，是否已经被读取了
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al
  jnz     seta20.2

  # 指令向控制器输入新的指令，0xdf
  movb    $0xdf,%al               # 0xdf -> port 0x60
  outb    %al,$0x60

  # Switch from real to protected mode, using a bootstrap GDT
  # and segment translation that makes virtual addresses 
  # identical to their physical addresses, so that the 
  # effective memory map does not change during the switch.

  # 把gdtdesc这个标识符的值送入全局映射描述符表寄存器GDTR中，把关于GDT表
  # 的一些重要信息存放到CPU的GDTR寄存器中，其中包括GDT表的内存起始地址，以
  # 及GDT表的长度，GDTR由48位组成，其中低16位表示该表长度，高32位表示该表在
  # 内存中的起始地址
  lgdt    gdtdesc

  #CR0寄存器,CR1~CR3寄存器都是80x86的控制寄存器
  #把CR0寄存器的bit0置1，CR0寄存器的bit0是保护模式启动位，把这一位置1代表保护模式启动
  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax
  movl    %eax, %cr0
  
  # Jump to next instruction, but in 32-bit code segment.
  # Switches processor into 32-bit mode.
  #  实模式跳转到保护模式
  ljmp    $PROT_MODE_CSEG, $protcseg

  .code32                     # Assemble for 32-bit mode
protcseg:
  # Set up the protected-mode data segment registers
  movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
  movw    %ax, %ds                # -> DS: Data Segment
  movw    %ax, %es                # -> ES: Extra Segment
  movw    %ax, %fs                # -> FS
  movw    %ax, %gs                # -> GS
  movw    %ax, %ss                # -> SS: Stack Segment
  
  # Set up the stack pointer and call into C.
  #设置当前的esp寄存器的值，然后正式跳转到main.c文件中的bootmain函数
  movl    $start, %esp
  call bootmain

  # If bootmain returns (it shouldn't), loop.
spin:
  jmp spin

# Bootstrap GDT
.p2align 2                                # force 4 byte alignment

# 由于xv6其实并没有使用分段机制，也就是说数据和代码都是写在一起的，所以数据段和
# 代码段的起始地址都是0x0，大小都是0xffffffff=4GB
gdt:
  SEG_NULL				# null seg
  SEG(STA_X|STA_R, 0x0, 0xffffffff)	    # code seg
  SEG(STA_W, 0x0, 0xffffffff)	        # data seg

gdtdesc:
  .word   0x17                            # sizeof(gdt) - 1
  .long   gdt                             # address gdt

