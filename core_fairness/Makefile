#OBJECT_FILES_NON_STANDARD_pre_helper.o := y
obj-m+=core.o
obj-m+=core2.o
obj-m+=test.o
obj-m+=calc.o
#write-objs= write_3.o  pre_helper.o


all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

