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


static int __init my_list_init(void)
{
	struct net_device *dev;
	struct net *net;
	int count=0,count2=0;;
	//read_lock(&dev_base_lock);
	//dev=first_net_device(&init_net);
	//while(dev){
	//	printk(KERN_INFO "%s %02x-%02x-%02x-%02x-%02x-%02x\n", dev->name, 
	//			dev->dev_addr[0],dev->dev_addr[1],dev->dev_addr[2],
	//			dev->dev_addr[3],dev->dev_addr[4],dev->dev_addr[5]);
	//	dev = next_net_device(dev);
	//}
	//read_unlock(&dev_base_lock);
	//
	
	rcu_read_lock();
	for_each_net_rcu(net){
		count++;
		dev=first_net_device(net);
		while(dev){
			printk(KERN_INFO "%s %02x-%02x-%02x-%02x-%02x-%02x\n", dev->name, 
					dev->dev_addr[0],dev->dev_addr[1],dev->dev_addr[2],
					dev->dev_addr[3],dev->dev_addr[4],dev->dev_addr[5]);
			dev = next_net_device(dev);
			count2++;
		}
	}
	rcu_read_unlock();
	printk(KERN_INFO "list init %d %d\n",count,count2);
    return 0;
}

static void __exit my_list_exit(void)
{
	printk(KERN_INFO "list exit\n");
}

module_init(my_list_init)
module_exit(my_list_exit)
MODULE_LICENSE("GPL");
