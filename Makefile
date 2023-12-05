CC=gcc
CFLAGS=-O0 -ggdb -Wall -Wextra -mno-red-zone

SYMLIB_DIR=../Symlib
SYMLIB_DYNAM_BUILD_DIR=$(SYMLIB_DIR)/dynam_build
SYMLIB_INCLUDE_DIR=$(SYMLIB_DIR)/include
SYMLIB_LINK=-L $(SYMLIB_DYNAM_BUILD_DIR) -lSym

KERNEL_LINK=-L ./ -lkernel
FORKU_LINK=-L./ -lforku

LINUX_PATH=~/Symbi-OS/linux
obj-m += forku.o

all: libforku.a forku_util malloc_spinner

libkernel.a: mklibkernel.sh
	./mklibkernel.sh

forku.o: forku.c
	make -C $(LINUX_PATH) M=$(PWD) modules_check
	rm .*.cmd forku.mod modules.order

libforku.a: libkernel.a forku.o
	ar rcs $@ forku.o

forku_util: forku_util.c libforku.a
	$(CC) $(CFLAGS) -I$(SYMLIB_INCLUDE_DIR) $^ -o $@ $(KERNEL_LINK) $(FORKU_LINK) $(SYMLIB_LINK)

malloc_spinner: spinner.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf *.o *.so *.s .*.d *.a core.* malloc_spinner forku_util
