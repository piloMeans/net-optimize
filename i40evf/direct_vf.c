/*
*   implementation
*/
#include "direct_vf.h"

// data vars
#define DEV_LIST_SZIE 256
DVF_DEV dvf_dev_list[DEV_LIST_SZIE]

// debug fc
inline void dvf_debug_echo_mac_addr(char * msg, unsigned char *macaddr){
    printk(KERN_INFO "%s %h:%h:%h:%h:%h:%h", msg, 
                                             macaddr[0], macaddr[1], macaddr[2],
                                             macaddr[3], macaddr[4], macaddr[5]);
}

// mac last index
static int dvf_mac_index(unsigned char* maddr){
    return (int) maddr[5];
}

// init dvf 
static void dvf_init(){
    memset(dvf_dev_list, 0, sizeof(DVF_DEV) * DEV_LIST_SZIE);
}

// exit dvf
static void dvf_exit(){
    dvf_init();
}

// add vf device
static void dev_add_vf_device(struct net_device *netdev){
    dvf_debug_echo_mac_addr("Add VF:", netdev->dev_addr);
    // TBD
}

// del vf device
static void dev_add_vf_device(struct net_device *netdev){
    dvf_debug_echo_mac_addr("Del VF:", netdev->dev_addr);
    // TBD
}

// direct send:
// return 0: success, else error
static u8 dev_add_vf_device(struct sk_buff *skb, struct net_device *netdev){
    //TBD
    return 0;
}
