/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when _do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever _do_fork() is invoked to create a new process.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#define VF_ARRAY_MAX 64

struct macAddr_list{
	struct macAddr_list *next;
	struct macAddr_list *rnext,*rprev;
	struct net_device * netdev;
	u8  status;
};

static struct macAddr_list vfarray[65];
static int vfarray_idx=0;

static struct macAddr_list *ready_vf ;

static struct macAddr_list *all_vf;

struct my_data{
	struct net_device *netdev;
};
static struct kretprobe kret_vfopen = {
	// the func open the vf
	// int ixgbevf_open(struct net_device *netdev);
	//.symbol_name  = "ixgbevf_open",
	//.symbol_name  = "macvlan_open",
	.data_size = sizeof(struct my_data),
	.maxactive = 20,
};
static struct kprobe kp_vfclose = {
	//int ixgbevf_open(struct net_device *netdev);
	//.symbol_name = "ixgbevf_close",
	.symbol_name = "macvlan_stop",
};
static struct kprobe kp_vfstartxmit = {
	//the func driver start xmit
	// static netdev_tx_t ixgbevf_xmit_frame(struct sk_buff *skb, 
	//						struct net_device *netdev);
	//.symbol_name = "ixgbevf_xmit_frame",
	.symbol_name = "macvlan_start_xmit",
}; 

static DEFINE_MUTEX(ready_mutex);
static DEFINE_MUTEX(all_mutex);

static int ret_handler_vfopen(struct kretprobe_instance *ri, struct pt_regs *regs){
	unsigned long retval = regs_return_value(regs);
	struct my_data *data;
	struct macAddr_list *tmp;
	if(retval)
		goto out;
	data = (struct my_data*)ri->data;	
	//travel all vf, if match with netdev
	//update
	tmp=all_vf;
	while(tmp){
		if(tmp->netdev == data->netdev){
			if(tmp->status == 0){
				// insert it into the ready_vf
					
				tmp->status = 1;

				mutex_lock(&ready_mutex);
				tmp->rnext = ready_vf;
				tmp->rprev = ready_vf->rprev;
				ready_vf=tmp;
				mutex_unlock(&ready_mutex);
			}
			goto out;
		}
		tmp=tmp->next;
	}

	if(vfarray_idx >= VF_ARRAY_MAX){
		printk(KERN_INFO "error, too much vf\n");
		goto failed;
	}
	mutex_lock(&all_mutex);
	tmp=&(vfarray[vfarray_idx]);
	tmp->next=all_vf;
	all_vf=tmp;
	vfarray_idx++;
	mutex_unlock(&all_mutex);	

	tmp->status=1;
	tmp->netdev = data->netdev;

	mutex_lock(&ready_mutex);
	tmp->rnext=ready_vf;	
	tmp->rprev = ready_vf->rprev;
	ready_vf=tmp;
	mutex_unlock(&ready_mutex);
out:
	return 0;
failed:
	return 1;
}
static int entry_vfopen(struct kretprobe_instance *ri, struct pt_regs *regs){
	struct my_data *data;
	if(!current->mm)
		return 1;
	data = (struct my_data *)(ri->data);
	data -> netdev = (struct net_device *)regs->di;
	return 0;
}
static int handler_pre_vfstartxmit(struct kprobe *p, struct pt_regs *regs){
	// find the macaddr in the ready list
	// if match,call dev_forward_skb and change the return address;
	struct macAddr_list *tmp=ready_vf;
	struct sk_buff *skb = (struct sk_buff *)regs->di;
	struct sk_buff *cskb;
	const struct ethhdr *eth = (void*)(skb->head + skb->mac_header);
	while(tmp && tmp->status && tmp->netdev){
		if(ether_addr_equal_64bits(eth->h_dest, tmp->netdev->dev_addr))
			goto diff;
		cskb = skb_clone(skb, GFP_ATOMIC);
		dev_forward_skb(tmp->netdev, cskb);
		skb->len = 0;	// should change the return val too ? 
						// actually it mess the statistics
		return 0;
diff:
		tmp=tmp->rnext;
	}
	return 1;
}

static int handler_pre_vfclose(struct kprobe *p, struct pt_regs *regs){
	// down the vf, find the netdev in macall, if match, unchained it in the ready list, and change the status.
	struct macAddr_list * tmp=ready_vf;
	struct net_device *target = (struct net_device *)regs->di;
	while(tmp && tmp->status){
		if(tmp->netdev == target){

			mutex_lock(&ready_mutex);
			tmp->rprev->rnext=tmp->rnext;
			tmp->rnext->rprev=tmp->rprev;
			mutex_unlock(&ready_mutex);

			tmp->rprev=NULL;
			tmp->rnext=NULL;
			tmp->status=0;
			goto out;
		}
		tmp=tmp->rnext;
	}
out:
	return 0;
}



#if 0
#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "_do_fork";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	pr_info("<%s> pre_handler: p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->ip, regs->flags);
#endif
#ifdef CONFIG_PPC
	pr_info("<%s> pre_handler: p->addr = 0x%p, nip = 0x%lx, msr = 0x%lx\n",
		p->symbol_name, p->addr, regs->nip, regs->msr);
#endif
#ifdef CONFIG_MIPS
	pr_info("<%s> pre_handler: p->addr = 0x%p, epc = 0x%lx, status = 0x%lx\n",
		p->symbol_name, p->addr, regs->cp0_epc, regs->cp0_status);
#endif
#ifdef CONFIG_ARM64
	pr_info("<%s> pre_handler: p->addr = 0x%p, pc = 0x%lx,"
			" pstate = 0x%lx\n",
		p->symbol_name, p->addr, (long)regs->pc, (long)regs->pstate);
#endif
#ifdef CONFIG_S390
	pr_info("<%s> pre_handler: p->addr, 0x%p, ip = 0x%lx, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->psw.addr, regs->flags);
#endif

	/* A dump_stack() here will give a stack backtrace */
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
#ifdef CONFIG_X86
	pr_info("<%s> post_handler: p->addr = 0x%p, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->flags);
#endif
#ifdef CONFIG_PPC
	pr_info("<%s> post_handler: p->addr = 0x%p, msr = 0x%lx\n",
		p->symbol_name, p->addr, regs->msr);
#endif
#ifdef CONFIG_MIPS
	pr_info("<%s> post_handler: p->addr = 0x%p, status = 0x%lx\n",
		p->symbol_name, p->addr, regs->cp0_status);
#endif
#ifdef CONFIG_ARM64
	pr_info("<%s> post_handler: p->addr = 0x%p, pstate = 0x%lx\n",
		p->symbol_name, p->addr, (long)regs->pstate);
#endif
#ifdef CONFIG_S390
	pr_info("<%s> pre_handler: p->addr, 0x%p, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->flags);
#endif
}
#endif
/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

static int __init kprobe_init(void)
{
	int ret;
#if 0
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
#endif

	ready_vf = &(vfarray[64]);	
	ready_vf->status=0;
	ready_vf->netdev = NULL;
	ready_vf->rnext=ready_vf;
	ready_vf->rprev=ready_vf;

	kret_vfopen.kp.symbol_name="macvlan_open";
	kret_vfopen.handler = ret_handler_vfopen;
	kret_vfopen.entry_handler = entry_vfopen;
	
	kp_vfclose.pre_handler = handler_pre_vfclose;
	kp_vfclose.post_handler = NULL;
	kp_vfclose.fault_handler = handler_fault;

	kp_vfstartxmit.pre_handler = handler_pre_vfstartxmit;
	kp_vfstartxmit.post_handler = NULL;
	kp_vfstartxmit.fault_handler = handler_fault;
	
	ret = register_kretprobe(&kret_vfopen);
	if(ret<0){
		goto failed;
	}
	ret = register_kprobe(&kp_vfclose);
	if(ret<0){
		goto failed1;	
	}
	ret = register_kprobe(&kp_vfstartxmit);
	if(ret<0){
		goto failed2;	
	}
	printk(KERN_INFO "register kprobe done\n");
	return 0;
failed2:
	unregister_kprobe(&kp_vfclose);
failed1:
	unregister_kretprobe(&kret_vfopen);	
failed:
	printk(KERN_INFO "register kprobe failed\n");
	return ret;
}

static void __exit kprobe_exit(void)
{
#if 0
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
#endif
	unregister_kretprobe(&kret_vfopen);
	unregister_kprobe(&kp_vfclose);
	unregister_kprobe(&kp_vfstartxmit);
	printk(KERN_INFO "unregistered kprobe done\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
