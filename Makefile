obj-m := halph-jiffie.o root-shell-from-segfault.o

KDIR := /lib/modules/$(shell uname -r)/build
PAGEFAULTDIR := page_fault
XPROBES := xprobes
PWD := $(shell pwd)
VERSION := 1.0

all:
	@echo "            .oO-HALPH-JIFFIE-$(VERSION)-Oo.\n"
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	$(MAKE) -C $(PWD)/$(PAGEFAULTDIR) 
	$(MAKE) -C $(PWD)/$(XPROBES)
	
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -rf *~ *.bz2 testfile
	$(MAKE) -C $(PWD)/$(XPROBES) clean
	$(MAKE) -C $(PWD)/$(PAGEFAULTDIR) clean
	
tarball: clean
	tar cjf halph-jiffie-$(VERSION).tar.bz2 *	