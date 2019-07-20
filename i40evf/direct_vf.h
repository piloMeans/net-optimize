/*
*   make vf path directly connected
*/


#ifndef _NI_DIRECT_VF_
#define _NI_DIRECT_VF_


/* include files */
#include <linux/types.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/if.h>
#include <linux/sk_buff.h>
#include <linux/etherdevice.h>
#include <linux/atomic.h>


/* data struct */
typedef struct {
    // stat
    u8 status;
    // netdev
    struct net_device *netdev;
} DVF_DEV, *DVF_DEV_REF;

#define DVF_STAT_NULL 0
#define DVF_STAT_NORMAL 1
#define DVF_STAT_EXCEPTION 2

// init dvf 
static void dvf_init();


// exit dvf
static void dvf_exit();


// add vf device
static void dvf_add_vf_device(struct net_device *netdev);


// del vf device
static void dvf_del_vf_device(struct net_device *netdev);


// direct send:
// return 0: success, else error
static u8 dvf_direct_send(struct sk_buff *skb, struct net_device *netdev);

#endif