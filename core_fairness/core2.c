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

//#define DEBUG
#define MYOWN
#define UNITSIZE 65536

// if the count of net_namespace > 1024,
// the kernel will boom
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

struct map_list{
	struct {
		struct net *net;
		u8 map[UNITSIZE];
		u16 status;
		u16 count;
	};
	struct map_list *next;
};

//struct map_unit maptable[MAPSIZE];
struct map_list maplist[MAPSIZE];
struct map_list map_head;
static int last=0;
static DEFINE_MUTEX(maplist_mutex);

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
static int (*__inet_check_established)(struct inet_timewait_death_row *death_row,
		struct sock *sk, __u16 lport, struct inet_timewait_sock **twp);
static __net_init int (*setup_net)(struct net *net, struct user_namespace *user_ns);
static struct net_generic *(*net_alloc_generic)(void);

#define dec_ucount  mydec_ucount
#define net_drop_ns mynet_drop_ns
#define inc_ucount myinc_ucount
#define __inet_bind my__inet_bind
#define __inet_hash_connect my__inet_hash_connect
static void (*dec_ucount)(struct ucounts *ucounts, enum ucount_type type);
static void (*net_drop_ns)(void *p);
static struct ucounts *(* inc_ucount)(struct user_namespace *ns, kuid_t uid, 
		enum ucount_type type);
static int (*__inet_hash_connect)(struct inet_timewait_death_row *death_row,
		struct sock *sk, u32 port_offset, 
		int (*check_established)(struct inet_timewait_death_row *, struct sock *, __u16,
			struct inet_timewait_sock **));
static int (*__inet_bind)(struct sock *sk, struct sockaddr *uaddr, int addr_len, 
		bool force_bind_address_no_port, bool with_lock);

static struct kmem_cache *net_cachep;

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
#else
#ifdef MYOWN
    	if ( (skb_shinfo(skb)->__unused & 0x30) != 0x30){
    	//if ( (skb_shinfo(skb)->__unused & 0x30) == 0x30){
#ifdef DEBUG
			printk(KERN_INFO "first time\n");
#endif
			skb_shinfo(skb)->__unused |= 0x30;
    		goto old;
		}
    	// only implement this for tcp and udp
    	if ( *(u16*)(skb->head + skb->mac_header + 12) != 0x0008){
#ifdef DEBUG
			printk(KERN_INFO "Not ip protocol\n");
#endif
    		goto old;
		}
    	u8 proto=*(u8*)(skb->head+skb->network_header + 9);
    	if ( proto != 0x11 && proto !=0x06){
#ifdef DEBUG
			printk(KERN_INFO "Not tcp/udp protocol\n");
#endif
    		goto old;
		}
		// veth_xmit set tag on skb_shinfo(skb)->_unused means it's packet for host
		// TODO
		//
		u8 mycpu;	
		unsigned int myqtail;
		u16 port;
		struct net *net;
		struct net_device *dev;
		struct net *dest_net=NULL;
		struct map_list *temp=map_head.next;
		//search the ns
		
		// get the dest macaddr
		u8 addr[8];

		memcpy(addr, (skb->head+skb->mac_header), 6);
		addr[6]=0;
		addr[7]=0;

		rcu_read_lock();
		for_each_net_rcu(net){
			dev = first_net_device(net);
			while(dev){
				if(ether_addr_equal_64bits(dev->dev_addr, addr)){
					dest_net = net;
					rcu_read_unlock();
					goto find;
				}
				dev = next_net_device(dev);
			}
		}
		rcu_read_unlock();
#ifdef DEBUG
		printk(KERN_INFO "Not found net\n");
#endif
		goto old;
find:
		while(temp!=NULL){
			if(temp->net == dest_net){
				goto find_1;
			}
			temp=temp->next;
		}
#ifdef DEBUG
		printk(KERN_INFO "Not found net2\n");
#endif
		goto old;
find_1:
		port = ntohs(*(u16*)(skb->head + skb->transport_header + 2));
		mycpu = temp->map[port];
		if (mycpu == 255){
#ifdef DEBUG
			printk(KERN_INFO "cpu is 255\n");
#endif
			goto old;
		}
		preempt_disable();
		ret=enqueue_to_backlog(skb, mycpu, &myqtail);
		preempt_enable();
		//skb_shinfo(skb)->__unused |= 0x30;
		goto out;
old:
		;
#endif
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
static int portbind(int port){
	if(!port)
		return 1;
	struct net *net=current->nsproxy->net_ns;

	u8 cpu=255;
	int tempcpu;
	u8 tempcount=0;
	//search the ns in the 
	struct map_list *temp=map_head.next;
	while(temp!=NULL){
		if(temp->net == net){
			// get one core in cpus_allowed
			temp->count++;	// lockless; atomic is not necessary
			
			//if(cpumask_next_zero(-1, &cpus_allowed) >= nr_cpu_ids)
			//	cpu=255;
			//else{
			tempcount = temp->count % current->nr_cpus_allowed;
			for_each_cpu(tempcpu, &(current->cpus_allowed)){
				if(!tempcount){
					cpu = tempcpu;
					break;
				}
				tempcount--;
			}
			//}
			temp->map[port] = cpu;
			return 0;
		}
		temp=temp->next;
	}
	return 1;
}
static u32 inet_sk_port_offset(const struct sock *sk){
	const struct inet_sock *inet = inet_sk(sk);
	return secure_ipv4_port_ephemeral(inet->inet_rcv_saddr,
			inet->inet_daddr,
			inet->inet_dport);
}
static int port_bind_func1(struct inet_timewait_death_row *death_row, struct sock* sk){
	u32 port_offset=0;
	int res;
	if(!inet_sk(sk)->inet_num)
		port_offset = inet_sk_port_offset(sk);
	res = __inet_hash_connect(death_row, sk, port_offset, __inet_check_established);

#ifdef MYOWN
	if(!res){
		u16 port = sk->sk_num;
		portbind(port);
	}
#endif
	return res;
	
}
static int port_bind_func2(struct socket *sock, struct sockaddr *uaddr, int addr_len){
	struct sock *sk = sock->sk;
	int err;
	if(sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	if(addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;
	err= BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr);
	if(err)
		return err;
	err=__inet_bind(sk, uaddr, addr_len, false, true);
#ifdef MYOWN
	if(!err){
		u16 port = sk->sk_num;
		portbind(port);
	}
#endif
	return err;
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
	u16 port = sk->sk_num;
	portbind(port);
#endif
	return 0;
}
static void dec_net_namespaces(struct ucounts *ucounts){
	dec_ucount(ucounts, UCOUNT_NET_NAMESPACES);
}
static void net_free(struct net *net){
	kfree(rcu_access_pointer(net->gen));
	kmem_cache_free(net_cachep, net);
}
static struct ucounts *inc_net_namespaces(struct user_namespace *ns){
	return inc_ucount(ns, current_euid(), UCOUNT_NET_NAMESPACES);
}
static struct net *net_alloc(void){
	struct net *net=NULL;
	struct net_generic *ng;
	ng=net_alloc_generic();
	if(!ng)
		goto out;
	net=kmem_cache_zalloc(net_cachep, GFP_KERNEL);
	if(!net)
		goto out_free;
	rcu_assign_pointer(net->gen, ng);
out:
	return net;
out_free:
	kfree(ng);
	goto out;
}
static struct net* ns_create_func(unsigned long flags, struct user_namespace *user_ns,
		struct net *old_net){
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
	// find one empty map_list 
	struct map_list *temp;
	int index;
find_emptylist:
	index=last;	
	while(maplist[index].status!=0) index++;
	
	temp=&(maplist[index]);

	//insert into the list
	//LOCK is needed
	mutex_lock(&maplist_mutex);
	last=index+1;
	if(last>=MAPSIZE)
		last=0;
	if(temp->status!=0){
		mutex_unlock(&maplist_mutex);
		goto find_emptylist;
	}
	temp->next=map_head.next;
	map_head.next=temp;
	temp->status=1;
	mutex_unlock(&maplist_mutex);
	temp->net = net;

#endif
	return net;	
}

static void ns_destroy_func(void *p){
	struct net *ns = p;
	if(ns && refcount_dec_and_test(&ns->passive)){
#ifdef MYOWN
		//search in the list, update the status
		// LOCK the list when update it
		// MAKE SURE the map find is not NULL, need check
		struct map_list *prev = &map_head;

		mutex_lock(&maplist_mutex);
		struct map_list *temp = map_head.next;
		while(temp!=NULL){
			if(temp->net == ns){

				memset(temp->map, 255, UNITSIZE);	

				// remove this maptable
				prev->next=temp->next;
				temp->net=NULL;
				temp->next=NULL;
				temp->status=0;
				goto find;
			}
			prev = prev->next;
			temp = temp->next;
		}
find:
		mutex_unlock(&maplist_mutex);
#endif
		net_free(ns);
	}
	
}
static int __init my_core_init(void)
{
	//printk(KERN_INFO "f addr is %p\n", my_run_sync);
	int i;
	struct net *net;
	
	for(i=0;i<MAPSIZE;i++){
		memset(maplist[i].map, 255, UNITSIZE);
		maplist[i].status=0;
		maplist[i].net=NULL;
		maplist[i].next=NULL;
		maplist[i].count=0;
	}
	map_head.next=NULL;

	addr3= (atomic_t *)kallsyms_lookup_name("modifying_ftrace_code");
	get_rps_cpu=(void *)kallsyms_lookup_name("get_rps_cpu");
	enqueue_to_backlog=(void *)kallsyms_lookup_name("enqueue_to_backlog");
	__inet_check_established = (void *)kallsyms_lookup_name("__inet_check_established");
	setup_net = (void*)kallsyms_lookup_name("setup_net");
	net_alloc_generic = (void *)kallsyms_lookup_name("net_alloc_generic");
	dec_ucount = (void *)kallsyms_lookup_name("dec_ucount");
	inc_ucount = (void *)kallsyms_lookup_name("inc_ucount");
	net_drop_ns = (void *)kallsyms_lookup_name("net_drop_ns");
	__inet_bind = (void *)kallsyms_lookup_name("__inet_bind");
	__inet_hash_connect = (void *)kallsyms_lookup_name("__inet_hash_connect");

	net_cachep = *(struct kmem_cache **)kallsyms_lookup_name("net_cachep");

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

	// add current exist netns into the list
	// for those already bind-port (not solved)
	rcu_read_lock();
	for_each_net_rcu(net){
		struct map_list *temp;
		int index;
find_emptylist:
		index=last;	
		while(maplist[index].status!=0) index++;
		
		temp=&(maplist[index]);
	
		//insert into the list
		//LOCK is needed
		mutex_lock(&maplist_mutex);
		last=index+1;
		if(last>=MAPSIZE)
			last=0;
		if(temp->status!=0){
			mutex_unlock(&maplist_mutex);
			goto find_emptylist;
		}
		temp->next=map_head.next;
		map_head.next=temp;
		temp->status=1;
		mutex_unlock(&maplist_mutex);
		temp->net = net;	
	}
	rcu_read_unlock();
    return 0;
}

static void __exit my_core_exit(void)
{
	code_restore( &my_func_table);
	code_restore( &port_bind1);
	code_restore( &port_bind2);
	code_restore( &port_bind3);
	code_restore( &ns_create);
	code_restore( &ns_destroy);
	printk(KERN_INFO "core exit\n");
}

module_init(my_core_init)
module_exit(my_core_exit)
MODULE_LICENSE("GPL");
