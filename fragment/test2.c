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
	u64 data;
	printk(KERN_INFO "test init\n");
	data= *(u64*)addr;
	printk(KERN_INFO "data there is %llx\n", data);
	addr = kallsyms_lookup_name("br_nf_dev_queue_xmit");
	data= *(u64*)addr;
	printk(KERN_INFO "data here is %llx\n", data);
	
    return 0;
}

static void __exit my_test_exit(void)
{
	printk(KERN_INFO "test exit\n");
}

module_init(my_test_init)
module_exit(my_test_exit)
MODULE_LICENSE("GPL");
