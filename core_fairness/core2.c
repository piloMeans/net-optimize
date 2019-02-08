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
#define UNITSIZE 65536
#define MAPSIZE 1024
struct func_table{
	unsigned long addr;
	u32 content;
	u8	origin;
	char name[30];
};
struct map_unit{
	int status;
	u8 map[UNITSIZE];
}


struct map_list{
	struct {
		struct net *net;
		struct map_unit *unit;
	};
	struct map_list *next;
};

struct map_unit maptable[MAPSIZE];
struct map_list maplist[MAPSIZE];
struct map_list map_head;

//unsigned long count=0;
// addr 3 is for atomic_modifying_code
atomic_t * addr3;
const unsigned char brk = 0xcc;
const unsigned char call= 0xe8;
const unsigned char jmp= 0xe9;
struct func_table my_func_table={
	.name = "netif_rx_internal",
};
struct func_table port_bind1={
	//.name="tcp_connect",
	.name="inet_hash_connect",
};
struct func_table port_bind2={
	.name="inet_bind",
};
struct func_table port_bind3={
	.name="inet_autobind",
};
struct func_table ns_create={
	.name="copy_net_ns",
};
struct func_table ns_destroy={
	.name="net_drop_ns",
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
		
#if 0
		u8 dest[6];
		int i;
		unsigned int myqtail;
		int mycpu;
		for(i=0;i<6;i++){
			dest[i]=*((u8*)(skb->head + skb->mac_header+i));
		}
		if(dest[0]!=0x02 || dest[1]!=0x42 || dest[2]!=0xac || dest[3]!=0x11 || 
				dest[4]!=0x00 || dest[5]>4)
			goto old;
		mycpu=dest[5]-1;
		preempt_disable();
		ret=enqueue_to_backlog(skb, mycpu, &myqtail);
		preempt_enable();
		goto out;
old:
		;
#endif
#ifdef MYOWN
		if ( port == 255)
			goto old;
		int mycpu;	
		unsigned int myqtail;

		//TODO  search the ns
		
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
static int portbind(int port, struct net *net){
	u8 cpu;
	//search the ns in the 
	struct map_list *temp=map_head.next;
	while(temp!=NULL){
		if(temp->net == net){
			// get one core in cpus_allowed
			// TODO
			cpu = select_one(cpus_allowed);
			temp->unit->map[port] = cpu;
			return 0;
		}
		temp=temp->next;
	}
	return 1;
}
static int port_bind_func1(struct inet_timewait_death_row *death_row, struct sock* sk){
	u32 port_offset=0;
	int res;
	if(!inet_sk(sk)->inet_num)
		port_offset = inet_sk_port_offset(sk);
	res = __inet_hash_connect(death_row, sk, port_offset, __inet_check_established);

#ifdef MYOWN
	struct net *mynet=current->nsproxy->net_ns;
	cpumask_t cpus_allowed = current->cpus_allowed;

	//TODO
	u16 port = xxxx;
	portbind(port, mynet);
#endif
	return res;
	
}
static int port_bind_func2(struct socket *sock, struct sockaddr *uaddr, int addr_len){
	struct sock *sk = sock->sk;
	int err;
#ifdef MYOWN
	u16 port = xxxx;
	struct net *mynet=current->nsproxy->net_ns;
	portbind(port, mynet);

#endif
	if(sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	if(addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;
	err= BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr);
	if(err)
		return err;
	return __inet_bind(sk, uaddr, addr_len, false, true);
}
static int port_bind_func3(struct sock *sk){
	struct inet_sock *inet;
	lock_sock(sk);
	inet = inet_sk(sk);
	if(!inet->inet_num){
		if(sk->sk_prot->get_port(sk,0)){
			release_sock(sk);
			return -EAGAIN;
		}
		inet->inet_sport = htons(inet->inet_num);

	}
	release_sock(sk);

#ifdef MYOWN
	u16 port = xxxx;
	struct net *mynet=current->nsproxy->net_ns;
	portbind(port, mynet);
#endif
	return 0;
}
static struct net* ns_create_func(){
	struct ucounts *ucounts;
	struct net *net;
	int rv;
	
	if (!(flags & CLONE_NEWNET))
		return get_net(old_net);

	ucounts = inc_net_namespaces(user_ns);
	if (!ucounts)
		return ERR_PTR(-ENOSPC);

	net = net_alloc();
	if (!net) {
		rv = -ENOMEM;
		goto dec_ucounts;
	}
	refcount_set(&net->passive, 1);
	net->ucounts = ucounts;
	get_user_ns(user_ns);

	rv = down_read_killable(&pernet_ops_rwsem);
	if (rv < 0)
		goto put_userns;

	rv = setup_net(net, user_ns);

	up_read(&pernet_ops_rwsem);

	if (rv < 0) {
put_userns:
		put_user_ns(user_ns);
		net_drop_ns(net);
dec_ucounts:
		dec_net_namespaces(ucounts);
		return ERR_PTR(rv);
	}
#ifdef MYOWN
	// TODO find one empty map_list and map_unit
	struct map_list *temp;
	struct map_unit *unit;
	temp = xxx;
	unit = xxx;
	
	temp->net = net;
	temp->unit = unit;

	//TODO insert into the list
	//TODO LOCK is needed
	temp->next=map_head.next;
	map_head.next=temp;

#endif
	return net;	
}
static void ns_destroy_func(void *p){
	struct net *ns = p;
	if(ns && refcount_dec_and_test(&ns->passive)){
#ifdef MYOWN
		//TODO search in the list, update the status
		// TODO LOCK the list when update it
		// TODO MAKE SURE the map find is not NULL, need check
		struct map_list *prev = &map_head;
		struct map_list *temp = map_head.next;
		while(temp!=NULL){
			if(temp->net == ns){

				temp->unit->status=0;
				memset(temp->unit->map, 255, UNITSIZE);	

				// remove this maptable
				prev->next=temp->next;
				temp->net=NULL;
				temp->unit=NULL;
				temp->next=NULL;
				goto find;
			}
			prev = prev->next;
			temp=temp->next;
		}
find:
#endif
		net_free(ns);
	}
	
}
static int __init my_core_init(void)
{
	//printk(KERN_INFO "f addr is %p\n", my_run_sync);
	int i;
	
	for(i=0;i<MAPSIZE;i++){
		maptable[i].status=0;
		memset(maptable[i].map, 255, UNITSIZE);
		maplist[i].net=NULL;
		maplist[i].unit=NULL;
		maplist[i].next=NULL;
	}
	map_head.next=NULL;

	addr3= (atomic_t *)kallsyms_lookup_name("modifying_ftrace_code");
	get_rps_cpu=(void *)kallsyms_lookup_name("get_rps_cpu");
	enqueue_to_backlog=(void *)kallsyms_lookup_name("enqueue_to_backlog");

	my_func_table.addr = kallsyms_lookup_name(my_func_table.name);
	if(my_func_table.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", my_func_table.name);
	}else{
		code_modify( &(my_func_table), (unsigned long)mycore_func);
	}
	port_bind1.addr = kallsyms_lookup_name(port_bind1.name);
	if(port_bind1.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", port_bind1.name);
	}else{
		code_modify( &(port_bind1), (unsigned long)port_bind_func1);
	}
	port_bind2.addr = kallsyms_lookup_name(port_bind2.name);
	if(port_bind2.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", port_bind2.name);
	}else{
		code_modify( &(port_bind2), (unsigned long)port_bind_func2);
	}
	port_bind3.addr = kallsyms_lookup_name(port_bind3.name);
	if(port_bind3.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", port_bind3.name);
	}else{
		code_modify( &(port_bind3), (unsigned long)port_bind_func3);
	}
	ns_create.addr = kallsyms_lookup_name(ns_create.name);
	if(ns_create.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", ns_create.name);
	}else{
		code_modify( &(ns_create), (unsigned long)ns_create_func);
	}
	ns_destroy.addr = kallsyms_lookup_name(ns_destroy.name);
	if(ns_destroy.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", ns_destroy.name);
	}else{
		code_modify( &(ns_destroy), (unsigned long)ns_destroy_func);
	}
	printk(KERN_INFO "core init\n");
    return 0;
}

static void __exit my_core_exit(void)
{
	code_restore( &my_func_table);
	code_restore( &port_bind1);
	code_restore( &port_bind2);
	code_restore( &port_bind3);
	code_restore( &ns_create_func);
	code_restore( &ns_destroy_func);
	printk(KERN_INFO "core exit\n");
}

module_init(my_core_init)
module_exit(my_core_exit)
MODULE_LICENSE("GPL");
