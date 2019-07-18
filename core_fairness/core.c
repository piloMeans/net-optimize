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

// header of 


#define MYOWN
int SEED = 0;
struct func_table{
	unsigned long addr;
	u32 content;
	u8	origin;
	char name[30];
};

//unsigned long count=0;
// addr 3 is for atomic_modifying_code
atomic_t * addr3;
const unsigned char brk = 0xcc;
const unsigned char call= 0xe8;
const unsigned char jmp= 0xe9;
struct func_table my_func_table={
	.name = "netif_rx_internal",
};

static int (*get_rps_cpu)(struct net_device *dev, struct sk_buff *skb,
		struct rps_dev_flow **rflowp);
static int (*enqueue_to_backlog)(struct sk_buff *skb, int cpu, unsigned int *qtail);

static void set_page_rw(unsigned long addr){
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if(pte->pte & (~_PAGE_RW))
		pte->pte |= _PAGE_RW;
}
static void set_page_ro(unsigned long addr){
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte & (~_PAGE_RW);
}
static void my_do_sync_core(void *data){
	sync_core();
}
static void my_run_sync(void){
	int enable_irqs;

	if(num_online_cpus() ==1)
		return;

	enable_irqs = irqs_disabled();

	if(enable_irqs)
		local_irq_enable();
	on_each_cpu(my_do_sync_core, NULL, 1);
	if(enable_irqs)
		local_irq_disable();
}



static void code_modify(struct func_table* func, unsigned long target_addr){

	unsigned long addr = func -> addr;
	u32 offset;
	if(addr==0)
		return;
	offset = target_addr - 5 - addr;
	func->content = *((u32 *)(addr+1));
	func->origin = *((u8*)addr);
	if(func->origin != 0x0f){	// not support reenter

		//legacy prefixes in https://wiki.osdev.org/X86-64_Instruction_Encoding
		if(func -> origin != 0x66 || func-> content != 0x90666666){		
			printk(KERN_ALERT "not support reenter function %s\n", func->name);
			func->addr=0;
			return ;
		}
	}
	
	set_page_rw(addr);
		
	smp_wmb();
	atomic_inc(addr3);

	probe_kernel_write((void*)addr, &brk, 1);
	my_run_sync();

	probe_kernel_write((void*)(addr+1), &offset, 4);
	
	my_run_sync();	

	//probe_kernel_write((void*)addr, &call, 1);
	probe_kernel_write((void*)addr, &jmp, 1);

	my_run_sync();	

	atomic_dec(addr3);
	set_page_ro(addr);

	
}
static void code_restore(struct func_table* func){
	unsigned long addr = func->addr;
	if(addr==0)
		return;
	set_page_rw(addr);

	smp_wmb();
	atomic_inc(addr3);
	probe_kernel_write((void*)addr, &brk, 1);

	my_run_sync();

	probe_kernel_write((void*)(addr+1), &(func->content), 4);
	
	my_run_sync();	

	probe_kernel_write((void*)addr, &(func->origin), 1);

	my_run_sync();	

	atomic_dec(addr3);
	set_page_ro(addr);

}

static int mycore_func(struct sk_buff *skb){
    int ret;

#ifndef MYOWN
    net_timestamp_check(netdev_tstamp_prequeue, skb);

    trace_netif_rx(skb);

    if (static_branch_unlikely(&generic_xdp_needed_key)) {
        int ret;

        preempt_disable();
        rcu_read_lock();
        ret = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), skb);
        rcu_read_unlock();
        preempt_enable();

        /* Consider XDP consuming the packet a success from
         * the netdev point of view we do not want to count
         * this as an error.
         */
        if (ret != XDP_PASS)
            return NET_RX_SUCCESS;
    }
#endif

#ifdef CONFIG_RPS
    if (static_key_false(&rps_needed)) {
        struct rps_dev_flow voidflow, *rflow = &voidflow;
        int cpu;

        preempt_disable();
        rcu_read_lock();
        cpu = get_rps_cpu(skb->dev, skb, &rflow);
        if (cpu < 0)
            cpu = smp_processor_id();

        ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);

        rcu_read_unlock();
        preempt_enable();
    } else
#endif
    {
		
#ifdef MYOWN
		u8 dest[6];
		int i;
		unsigned int myqtail;
		int mycpu;
		for(i=0;i<6;i++){
			dest[i]=*((u8*)(skb->head + skb->mac_header+i));
		}
		if(dest[0]!=0x02 || dest[1]!=0x42 || dest[2]!=0xac || dest[3]!=0x11 || 
				dest[4]!=0x00 || dest[5]!=0x03)
			goto old;
		SEED += 1;
                if ( (skb_shinfo(skb)->__unused & 0x30) != 0x30){
                        skb_shinfo(skb)->__unused |= 0x30;
                        mycpu = 2; //+ SEED % 2;//client core, 2 or 3
                } else {
                        mycpu= 4 + SEED % 2;//server core, 4 or 5
                }
		preempt_disable();
		ret=enqueue_to_backlog(skb, mycpu, &myqtail);
		preempt_enable();
		goto out;
old:
		;
#endif
        unsigned int qtail;

        ret = enqueue_to_backlog(skb, get_cpu(), &qtail);
        put_cpu();
    }
#ifdef MYOWN
out:
#endif
    return ret;
}
static int __init my_core_init(void)
{
	//printk(KERN_INFO "f addr is %p\n", my_run_sync);
	
	addr3= (atomic_t *)kallsyms_lookup_name("modifying_ftrace_code");
	get_rps_cpu=(void *)kallsyms_lookup_name("get_rps_cpu");
	enqueue_to_backlog=(void *)kallsyms_lookup_name("enqueue_to_backlog");

	my_func_table.addr = kallsyms_lookup_name(my_func_table.name);
	if(my_func_table.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", my_func_table.name);
	}else{
		code_modify( &(my_func_table), (unsigned long)mycore_func);
	}
	printk(KERN_INFO "core init\n");
    return 0;
}

static void __exit my_core_exit(void)
{
	code_restore( &my_func_table);
	printk(KERN_INFO "core exit\n");
}

module_init(my_core_init)
module_exit(my_core_exit)
MODULE_LICENSE("GPL");
