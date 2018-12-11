#CONFIG_MODULE_FORCE_UNLOAD=y
#override EXTRA_CFLAGS+= -O0


#CONFIG_MODULES_SIG=n

#obj-m+=write.o
#write-objs= write_3.o  pre_helper.o
obj-m+=optimize.o


all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

