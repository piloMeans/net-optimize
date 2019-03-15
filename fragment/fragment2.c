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


//  headers of net/ipv4/ip_output.c
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/lwtunnel.h>
#include <linux/bpf-cgroup.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

//#include <linux/netfilter_ipv6.h>
#include <net/netfilter/br_netfilter.h>

#define MYOWN
struct func_table{
	unsigned long addr;
	u32 content;
	u8	origin;
	char name[30];
};

#if 0
#define NF_BRIDGE_MAX_MAC_HEADER_LENGTH (PPPOE_SES_HLEN + ETH_HLEN)
struct brnf_frag_data {
	char mac[NF_BRIDGE_MAX_MAC_HEADER_LENGTH];
	u8 encap_size;
	u8 size;
	u16 vlan_tci;
	__be16 vlan_proto;
};
struct brnf_frag_data * brnf_frag_data_storage;
#endif

//unsigned long count=0;
// addr 3 is for atomic_modifying_code
atomic_t * addr3;

const unsigned char brk = 0xcc;
const unsigned char call= 0xe8;
const unsigned char jmp= 0xe9;
struct func_table my_func1={
	.name = "ip_finish_output"
};
struct func_table my_func2={
	.name = "is_skb_forwardable"
};
struct func_table my_func3={
	.name = "br_nf_dev_queue_xmit"
};

static int (*ip_fragment)(struct net *net, struct sock *sk, struct sk_buff *skb,
	unsigned int mtu, int(*output)(struct net *, struct sock *, struct sk_buff *));
static int (*ip_finish_output2)(struct net *net, struct sock *sk, struct sk_buff *skb);
//static int (*br_dev_queue_push_xmit)(struct net *net, struct sock *sk, struct sk_buff *skb);
#if 0
static int (*br_validate_ipv4)(struct net *net, struct sk_buff *skb);
static int (*br_validate_ipv6)(struct net *net, struct sk_buff *skb);
static void (*nf_bridge_update_protocol)(struct sk_buff *skb);
static int (*br_nf_push_frag_xmit)(struct net *net, struct sock *sk, struct sk_buff *skb);
#endif

//static int (*ip_finish_output_gso)(struct net *net, struct sock *sk, 
//	struct sk_buff *skb, unsigned int mtu);


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
static int is_target_host(struct neighbour *neigh){
	struct net *net;
	struct net_device *dev;
	union {
		u8 addr[8];
		u64 hh_data;
	} target;
	target.hh_data = (neigh->hh.hh_data[0])>>16;

	rcu_read_lock();
	for_each_net_rcu(net){
		dev=first_net_device(net);
		while(dev){
			if(ether_addr_equal_64bits(dev->dev_addr, target.addr)){
				rcu_read_unlock();
				return 1;
			}
			dev = next_net_device(dev);
		}
	}
	rcu_read_unlock();
	return 0;
}
static int ip_finish_output_gso(struct net *net, struct sock *sk, 
	struct sk_buff *skb, unsigned int mtu){
	netdev_features_t features;
    struct sk_buff *segs;
    int ret = 0;

    if (skb_gso_validate_network_len(skb, mtu))
        return ip_finish_output2(net, sk, skb);

    features = netif_skb_features(skb);
    BUILD_BUG_ON(sizeof(*IPCB(skb)) > SKB_SGO_CB_OFFSET);
    segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
    if (IS_ERR_OR_NULL(segs)) {
        kfree_skb(skb);
        return -ENOMEM;
    }
	consume_skb(skb);

    do {
        struct sk_buff *nskb = segs->next;
        int err;

        segs->next = NULL;
        err = ip_fragment(net, sk, segs, mtu, ip_finish_output2);

        if (err && ret == 0)
            ret = err;
        segs = nskb;
    } while (segs);

    return ret;
}
static int myfunc1(struct net *net, struct sock *sk, struct sk_buff *skb){
	unsigned int mtu;
	int ret;

#ifdef MYOWN
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt=(struct rtable *)dst;
	struct neighbour *neigh;
	u32 nexthop;
	struct net_device *dev=dst->dev;
#endif
    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
    /* Policy lookup after SNAT yielded a new policy */
    if (skb_dst(skb)->xfrm) {
        IPCB(skb)->flags |= IPSKB_REROUTED;
        return dst_output(net, sk, skb);
    }
#endif
    mtu = ip_skb_dst_mtu(sk, skb);
    if (skb_is_gso(skb))
        return ip_finish_output_gso(net, sk, skb, mtu);
#ifdef MYOWN
	if (skb->len > mtu){

		rcu_read_lock_bh();

		nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
		neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
		if(unlikely(!neigh))
			neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
		if(!IS_ERR(neigh)){
			//printk(KERN_INFO "actually run here\n");
			if(is_target_host(neigh)){
				//if(count%100000==0)
				//	printk(KERN_INFO "LOCAL detected\n");
				//count++;
				//printk(KERN_INFO "run here\n");
				skb_shinfo(skb)->__unused |= 0xc0;
				rcu_read_unlock_bh();
				return ip_finish_output2(net, sk, skb);
			}
		}
		rcu_read_unlock_bh();
	}
#endif

    if (skb->len > mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU))
        return ip_fragment(net, sk, skb, mtu, ip_finish_output2);


    return ip_finish_output2(net, sk, skb);
}
static bool myfunc2(const struct net_device *dev, const struct sk_buff *skb){
	unsigned int len;
	if(!(dev->flags & IFF_UP))
		return false;
	len = dev->mtu + dev->hard_header_len + VLAN_HLEN;
	if(skb->len <= len)
		return true;
#ifdef MYOWN
	else if( skb_shinfo(skb) && (skb_shinfo(skb)->__unused & 0xc0)==0xc0){
		//printk(KERN_INFO "here?\n");
		return true;
	}
#endif
	if(skb_is_gso(skb))
		return true;
	return false;
}

static unsigned int nf_bridge_mtu_reduction(const struct sk_buff *skb){
	if(skb->nf_bridge->orig_proto == BRNF_PROTO_PPPOE)
		return PPPOE_SES_HLEN;
	return 0;
}
static void nf_bridge_info_free(struct sk_buff *skb){
	if(skb->nf_bridge){
		nf_bridge_put(skb->nf_bridge);
		skb->nf_bridge=NULL;
	}
}
#if 0
static unsigned int nf_bridge_encap_header_len(const struct sk_buff *skb){
	switch(skb->protocol){
		case __cpu_to_be16(ETH_P_8021Q):
			return VLAN_HLEN;
		case __cpu_to_be16(ETH_P_PPP_SES):
			return PPPOE_SES_HLEN;
		default:
			return 0;
	}
}
static int br_nf_ip_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		int (*output)(struct net *, struct sock *, struct sk_buff *)){
	unsigned int mtu = ip_skb_dst_mtu(sk, skb);
	struct iphdr *iph = ip_hdr(skb);

	if (unlikely(((iph->frag_off & htons(IP_DF)) && !skb->ignore_df) ||
		     (IPCB(skb)->frag_max_size &&
		      IPCB(skb)->frag_max_size > mtu))) {
		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	return ip_do_fragment(net, sk, skb, output);	
}
#endif

static int myfunc3(struct net *net, struct sock *sk, struct sk_buff *skb){
	struct nf_bridge_info *nf_bridge = nf_bridge_info_get(skb);
	unsigned int mtu, mtu_reserved;

	mtu_reserved = nf_bridge_mtu_reduction(skb);
	mtu = skb->dev->mtu;

	if (nf_bridge->frag_max_size && nf_bridge->frag_max_size < mtu)
		mtu = nf_bridge->frag_max_size;

	if (skb_is_gso(skb) || skb->len + mtu_reserved <= mtu) {
		nf_bridge_info_free(skb);
		return br_dev_queue_push_xmit(net, sk, skb);
	}

	/* This is wrong! We should preserve the original fragment
	 * boundaries by preserving frag_list rather than refragmenting.
	 */
#if 0
	if (IS_ENABLED(CONFIG_NF_DEFRAG_IPV4) &&
	    skb->protocol == htons(ETH_P_IP)) {
		struct brnf_frag_data *data;

		if (br_validate_ipv4(net, skb))
			goto drop;

		IPCB(skb)->frag_max_size = nf_bridge->frag_max_size;

		nf_bridge_update_protocol(skb);

#ifdef MYOWN
		data = this_cpu_ptr(brnf_frag_data_storage);
#else
		data = this_cpu_ptr(&brnf_frag_data_storage);
#endif

		data->vlan_tci = skb->vlan_tci;
		data->vlan_proto = skb->vlan_proto;
		data->encap_size = nf_bridge_encap_header_len(skb);
		data->size = ETH_HLEN + data->encap_size;

		skb_copy_from_linear_data_offset(skb, -data->size, data->mac,
						 data->size);

		return br_nf_ip_fragment(net, sk, skb, br_nf_push_frag_xmit);
	}
	if (IS_ENABLED(CONFIG_NF_DEFRAG_IPV6) &&
	    skb->protocol == htons(ETH_P_IPV6)) {
		const struct nf_ipv6_ops *v6ops = nf_get_ipv6_ops();
		struct brnf_frag_data *data;

		if (br_validate_ipv6(net, skb))
			goto drop;

		IP6CB(skb)->frag_max_size = nf_bridge->frag_max_size;

		nf_bridge_update_protocol(skb);

#ifdef MYOWN
		data = this_cpu_ptr(brnf_frag_data_storage);
#else
		data = this_cpu_ptr(&brnf_frag_data_storage);
#endif
		data->encap_size = nf_bridge_encap_header_len(skb);
		data->size = ETH_HLEN + data->encap_size;

		skb_copy_from_linear_data_offset(skb, -data->size, data->mac,
						 data->size);

		if (v6ops)
			return v6ops->fragment(net, sk, skb, br_nf_push_frag_xmit);

		kfree_skb(skb);
		return -EMSGSIZE;
	}
#endif
	nf_bridge_info_free(skb);
	return br_dev_queue_push_xmit(net, sk, skb);
 drop:
	kfree_skb(skb);
	return 0;
}
static int __init my_fragment_init(void)
{
	//printk(KERN_INFO "f addr is %p\n", my_run_sync);
	
	addr3= (atomic_t *)kallsyms_lookup_name("modifying_ftrace_code");

	//ip_finish_output_gso = (void*)kallsyms_lookup_name("ip_finish_output_gso");
	ip_fragment = (void*)kallsyms_lookup_name("ip_fragment.constprop.49");
	ip_finish_output2 =  (void*)kallsyms_lookup_name("ip_finish_output2");
	//br_dev_queue_push_xmit = (void*)kallsyms_lookup_name("br_dev_queue_push_xmit");
#if 0
	br_validate_ipv4 = (void*)kallsyms_lookup_name("br_validate_ipv4.isra.27");
	br_validate_ipv6 = (void*)kallsyms_lookup_name("br_validate_ipv6");
	nf_bridge_update_protocol = (void*)kallsyms_lookup_name("nf_bridge_update_protocol");
	brnf_frag_data_storage = (struct brnf_frag_data *)kallsyms_lookup_name("brnf_frag_data_storage");
	br_nf_push_frag_xmit = (void*)kallsyms_lookup_name("br_nf_push_frag_xmit");
	//nf_ipv6_ops = (void*)kallsyms_lookup_name("nf_ipv6_ops");
#endif

	if(ip_fragment==NULL || ip_finish_output2==NULL ){//|| br_dev_queue_push_xmit==NULL){
		printk(KERN_INFO "func not found\n");
	}
	
	my_func1.addr = kallsyms_lookup_name(my_func1.name);
	if(my_func1.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", my_func1.name);
	}else{
		code_modify( &(my_func1), (unsigned long)myfunc1);
	}
	my_func2.addr = kallsyms_lookup_name(my_func2.name);
	if(my_func2.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", my_func2.name);
	}else{
		code_modify( &(my_func2), (unsigned long)myfunc2);
	}
	my_func3.addr = kallsyms_lookup_name(my_func3.name);
	if(my_func3.addr==0){
		printk(KERN_INFO "function %s not found in kallsyms\n", my_func3.name);
	}else{
		code_modify( &(my_func3), (unsigned long)myfunc3);
	}
	printk(KERN_INFO "fragment init\n");
    return 0;
}

static void __exit my_fragment_exit(void)
{
	code_restore( &my_func1);
	code_restore( &my_func2);
	code_restore( &my_func3);
	printk(KERN_INFO "fragment exit\n");
}

module_init(my_fragment_init)
module_exit(my_fragment_exit)
MODULE_LICENSE("GPL");
