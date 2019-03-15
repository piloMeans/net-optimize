#OBJECT_FILES_NON_STANDARD_pre_helper.o := y
obj-m+=fragment.o
obj-m+=fragment2.o
obj-m+=list.o
obj-m+=test2.o
#write-objs= write_3.o  pre_helper.o


all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

