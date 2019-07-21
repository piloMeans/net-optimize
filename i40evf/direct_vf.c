/*
*   implementation
*/
#include "direct_vf.h"

// data vars
#define DEV_LIST_SZIE 260
DVF_DEV dvf_dev_list[DEV_LIST_SZIE];

// dev list operate lock
static DEFINE_MUTEX(dvf_dev_list_lock);

// debug function
inline void dvf_debug_echo_mac_addr(char * msg, unsigned char *macaddr){
    printk(KERN_INFO "%s %2x:%2x:%x:%2x:%2x:%2x", msg, 
                                                  macaddr[0], macaddr[1], macaddr[2],
                                                  macaddr[3], macaddr[4], macaddr[5]);
}

// mac last index
inline int dvf_mac_index(const unsigned char* maddr){
    return (int) maddr[5];
}

// init dvf 
void dvf_init(void){
    mutex_lock(&dvf_dev_list_lock);
    memset(dvf_dev_list, 0, sizeof(DVF_DEV) * DEV_LIST_SZIE);
    mutex_unlock(&dvf_dev_list_lock);
}

// exit dvf
void dvf_exit(void){
    dvf_init();
}

// add vf device
void dvf_add_vf_device(struct net_device *netdev){
    int idx;
    DVF_DEV_REF node;

    idx = dvf_mac_index(netdev->dev_addr);
    node = &dvf_dev_list[idx];
    dvf_debug_echo_mac_addr("Add VF: ", netdev->dev_addr);

    if(node->status != DVF_STAT_NULL){
        printk(KERN_INFO"ADD INF, VF_DEV[%d] existed, maybe error[stat=%d]", idx, node->status);
    }

    // set record
    mutex_lock(&dvf_dev_list_lock);
    node->status = DVF_STAT_NORMAL;
    node->netdev = netdev;
    mutex_unlock(&dvf_dev_list_lock);
    
    // End
}


// del vf device
void dvf_del_vf_device(struct net_device *netdev){
    int idx;
    DVF_DEV_REF node;

    dvf_debug_echo_mac_addr("Del VF: ", netdev->dev_addr);
    
    idx = dvf_mac_index(netdev->dev_addr);
    node = &dvf_dev_list[idx];

    // check validate
    if(node->status == DVF_STAT_NULL){
        printk(KERN_INFO"DEL INF, VF_DEV[%d] not find, maybe error[stat=%d]", idx, node->status);
        return;
    }

    // clear node
    mutex_lock(&dvf_dev_list_lock);    
    node->status = DVF_STAT_NULL;
    node->netdev = NULL;
    memset(node, 0, sizeof(DVF_DEV));
    mutex_unlock(&dvf_dev_list_lock);
}


// direct send:
// return 0: success, else error
u8 dvf_direct_send(struct sk_buff *skb, struct net_device *netdev){
    int idx;
    DVF_DEV_REF node;
    const struct ethhdr *eth = (void *)(skb->head + skb->mac_header );

    // send to self.netdev ignore
    if(ether_addr_equal(eth->h_dest, netdev->dev_addr)){
        return 1;
    }

    // find netdev
    idx = dvf_mac_index(eth->h_dest);
    node = &dvf_dev_list[idx];

    // check mapped VF
    if(node->status == DVF_STAT_NORMAL){
        if(ether_addr_equal(eth->h_dest, node->netdev->dev_addr)){

            // direct send
            dev_forward_skb(node->netdev, skb);
            return 0;
        }
    }

    // End
    return 1;
}

