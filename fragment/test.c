/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever do_fork() is invoked to create a new process.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <asm/ftrace.h>
#include <linux/smp.h>
#include <uapi/linux/time.h>
#include <linux/cpumask.h>
#include <asm/current.h>
#include <uapi/linux/ip.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/jhash.h>
#include <asm/atomic.h>
#include <asm/cmpxchg.h>


static int __init my_test_init(void)
{
	unsigned long addr = kallsyms_lookup_name("ip_finish_output2");
	u8 op;
	union{
		u8 data_8[4];
		u32 data_32;
	} Data;

	printk(KERN_INFO "test init\n");

	if(addr){
		op=*(u8*)addr;	
		Data.data_32=*(u32*)(addr+1);
	printk(KERN_INFO "op is %02x rest is %02x %02x %02x %02x\n",op, Data.data_8[0],
			Data.data_8[1],Data.data_8[2],Data.data_8[3]);
	}
	
    return 0;
}

static void __exit my_test_exit(void)
{
	printk(KERN_INFO "test exit\n");
}

module_init(my_test_init)
module_exit(my_test_exit)
MODULE_LICENSE("GPL");
