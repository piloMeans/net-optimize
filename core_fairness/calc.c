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
#include <net/secure_seq.h>
#include <net/netns/generic.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
// header of 


#define MYOWN
#define UNITSIZE 65536
#define MAPSIZE 1024
struct func_table{
	unsigned long addr;
	u32 content;
	u8	origin;
	char name[30];
};
/*
struct map_unit{
	int status;
	u8 map[UNITSIZE];
}
*/

//unsigned long count=0;
// addr 3 is for atomic_modifying_code
atomic_t * addr3;
unsigned int *mynr_cpu_ids;
const unsigned char brk = 0xcc;
const unsigned char call= 0xe8;
const unsigned char jmp= 0xe9;
struct func_table func1={
	.name = "ip_local_out",
};
struct func_table func2={
	//.name="tcp_connect",
	.name="udp_rcv",
};

u64 count_send=0;
u64 count_recv=0;

static int (*__udp4_lib_rcv)(struct sk_buff *skb, struct udp_table *udptable, int proto);
struct udp_table *udp_table;
static int (*__ip_local_out)(struct net *net, struct sock *sk, struct sk_buff *skb);

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
static int myfunc1(struct net *net, struct sock *sk, struct sk_buff *skb){
	int err;
	u16 port = *(u16*)(skb->head + skb->transport_header + 2);
	if(port== 0xa05b)
		count_send++;

	err = __ip_local_out(net, sk, skb);
	if(likely(err==1)){
		err = skb_dst(skb)->output(net,sk,skb);
	}
	return err;
}
static int myfunc2(struct sk_buff *skb){

	u16 port = *(u16*)(skb->head + skb->transport_header + 2);
	if(port== 0xa05b)
		count_recv++;
	return __udp4_lib_rcv(skb, udp_table, IPPROTO_UDP);
}

static int __init my_core_init(void)
{
	addr3= (atomic_t *)kallsyms_lookup_name("modifying_ftrace_code");
	udp_table= (struct udp_table*)kallsyms_lookup_name("udp_table");
	__ip_local_out = (void *)kallsyms_lookup_name("__ip_local_out");
	__udp4_lib_rcv = (void *)kallsyms_lookup_name("__udp4_lib_rcv");


	func1.addr = kallsyms_lookup_name(func1.name);
	if(func1.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", func1.name);
	}else{
		code_modify( &(func1), (unsigned long)myfunc1);
	}
	
	func2.addr = kallsyms_lookup_name(func2.name);
	if(func2.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", func2.name);
	}else{
		code_modify( &(func2), (unsigned long)myfunc2);
	}

	printk(KERN_INFO "core init\n");
    return 0;
}

static void __exit my_core_exit(void)
{

	printk(KERN_INFO "send %lld recv %lld\n", count_send, count_recv);
	code_restore( &func1);
	code_restore( &func2);
	printk(KERN_INFO "core exit\n");
}

module_init(my_core_init)
module_exit(my_core_exit)
MODULE_LICENSE("GPL");
