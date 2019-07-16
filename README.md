# Problem 

we developped a tool ![ftrace_based_trace](https://gitlab.com/plehdeen/ftrace_baesd_trace) to profile the pkt behavior in the kernel.

## ovs vs sriov

We found that the sriov is slow than the ovs when doing net communication between containers in a host.

In sriov situation, we bind the vf of NIC to contianer directly.


```

   +---------+    +---------+
   |         |    |         |
   | Docker1 |    |  Docker2|
   +----+----+    +----+----+
        |              |
  +---------------------------+
  |     |              |      |
  |  +--+---+      +---+--+   |
  |  | VF1  |      |  VF2 |   |
  |  +------+      +------+   |
  | NIC                       |
  +---------------------------+

```

In ovs situation, we set the two containers in one subnet and connected with ovs.

```
+---------+    +---------+
|         |    |         |
| Docker1 |    |  Docker2|
+------+--+    +--+------+
       |          |
       |          |
     +-+----------+--+
     |     OVS       |
     +---------------+

```

And we found that the behavior of this two situation is nearly same expect the stage between VF1 and VF2. 

In the sriov situation, the pkt is not the same one so the time consumed there is much more than OVS situation.


## tcp vs udp in netperf STREAM mode

we find that udp is always slower than tcp when using netperf STREAM mode, this situation is more serious when experiment between 
containers in a host.

through the tool, we find that the udp is much slower because of fragmentation and defragmentation.

## core fairness question

we find that the sender always cover too much part even that's should be done by the receiver when network communication between 
containers in one host .

e.g. the sender core will deal with the packet util the recviver process wakeup (YES, the network stack part after the sortirq is 
still under control of sender.) This kind of situation make that the receiver "steal" some cpu from sender. so when the network
communication between them is not symmetry, the senders ability will be limited.

```
           +--------+                                  +--------+
           | sender |                                  |receiver|
           +----+---+                                  +----+---+
                |                                           |            userspace
+---------------------------------------------------------------------------------+
                |                                           |            kernelspace
                |                                           | <-----+
                |         softirq send pkt                  |       |
                |         to another    |                   |       |
                |         namespace     |                   |       +-----+
                |                       |                   |         wake up the
                +-------------------------------------------+         receiver
                                        |
                                        |
                                        |

```

# Optimize method

## problem 1 

- build a MacAddr-table of VF
- forward the pkt to the specific dev if dst_MAC is in the table.

In this way, we donot need to copy the entire pkt and rebuild a pkt. And it works!

## problem 2 

I check the route target of the pkt which is more thatn mtu, if the destination is belong to host, then 
the fragmentation should not be done. 

I write a linux module to optimize that.

## problem 3

I check the route target again, and if the destination if belong to host, I insert pkt into the correspond core.

The Question is 
determine the core. it's diffcult to determine,  because the network namespace can bind with different kind of 
user namespace(and the cpuset of them may be different). so we must consider the port in it. And I must modify 
a bunch of code to implement that.

Still under development. 

And I took some experiment when just bind the network namespace with only one core. and the result is good after 
reassigning the core.

# How to build

## sriov
This driver code needs to be built together with linux source code.  
- [Attention!] This code is only tested in `linux 4.19.0`.  
- First, download[](https://www.kernel.org/) the linux kernel sourc code. If you use the default kernel, you can also use the `/usr/src` things.  
- Second, replace the driver code in the corresponding kernel source code directory: `drivers/net/ethernet/intel/ixgbevf/`
- Third, run `make oldconfig` and `make prepare` to do some preparing work. [Optional, or when if something goes wrong]  
- Forth, to only build the target module (not the whole kernel), run `make SUBDIRS=/path/to/driver` under kernel src code root directory.  

## the rest
They can be built under this project's directory, and not needed to build with kernel code.  
Just run `make`.

### TroubleShooting

Q: the `make command` not work

A: you should do these in the src code root directory.

Q: When bulid the driver, `script/mod/modpost` not found

A: run `make SUBDIRS=script/mod/` first to generate modpost

Q: What if the directory contains serveral drivers, but I only want to get one of them?

A: run `make path/to/driver/name.ko` to get single driver. if modpost too much drivers, you can change the Makefile.


# How to use the module
1. Check if the original module is running:
```
lsmod | grep $module_name
```
2. Stop sriov
```
echo 0 > /sys/class/net/enp129s0f0/device/sriov_numvfs
```
3. Install module
```
insmod
```
4. Remove module
```
rm
```

