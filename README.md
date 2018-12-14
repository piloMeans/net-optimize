
# Problem 

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

we developped a tool ![ftrace_based_trace](https://gitlab.com/plehdeen/ftrace_baesd_trace) to profile the pkt behavior in the kernel.

## What we find for now

And we found that the behavior of this two situation is nearly same expect the stage between VF1 and VF2. 

In the sriov situation, the pkt is not the same one so the time consumed there is much more than OVS situation.

#### Optimize method

- build a MacAddr-table of VF
- forward the pkt to the specific dev if dst_MAC is in the table.

In this way, we donot need to copy the entire pkt and rebuild a pkt. Hope it works!


## How to build

- Attention, this code only tested in `linux 4.19.0`.
- First, download the linux kernel src code. If you use the default kernel, you can also use the `/usr/src` things.
- Second, replace the driver code.
- Third, run `make oldconfig` and `make prepare` to do some preparing work.
- Forth, run `make SUBDIRS=/path/to/driver` to build the target module

#### TroubleShooting

Q: the `make command` not work

A: you should do these in the src code root directory.

Q: When bulid the driver, `script/mod/modpost` not found

A: run `make SUBDIRS=script/mod/` first to generate modpost

Q: What if the directory contains serveral drivers, but I only want to get one of them?

A: run `make path/to/driver/name.ko` to get single driver. if modpost too much drivers, you can change the Makefile.

