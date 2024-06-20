obj-m = kcrypto_netpkt_mod.o
#KVERSION = $(shell uname -r)
KVERSION = 5.14.21-150400.24.100-default
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
