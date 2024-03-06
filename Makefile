CC=gcc
CFLAGS=-O0 -g -Wall -Wextra -mno-red-zone -m64

SYMLIB_DIR=../Symlib
SYMLIB_DYNAM_BUILD_DIR=$(SYMLIB_DIR)/dynam_build
SYMLIB_INCLUDE_DIR=$(SYMLIB_DIR)/include
SYMLIB_LINK=-L $(SYMLIB_DYNAM_BUILD_DIR) -lSym

KERNEL_LINK=-L ./ -lkernel
FORKU_LINK=-L./ -lforku
SNAPSHOT_LINK=-L./ -lsnapshot

FUSE_FLAGS=`pkg-config fuse --cflags --libs`

LINUX_PATH=~/Symbi-OS/linux
obj-m += forku.o

all: libforku.a libsnapshot.a forku_util forku_monitord malloc_spinner

libkernel.a: mklibkernel.sh
	./mklibkernel.sh

forku.o: forku.c
	make -C $(LINUX_PATH) M=$(PWD) modules_check
	rm .*.cmd forku.mod modules.order

libforku.a: libkernel.a forku.o
	ar rcs $@ forku.o

snapshot.o: libkernel.a libforku.a snapshot.c
	$(CC) $(CFLAGS) -I$(SYMLIB_INCLUDE_DIR) -c snapshot.c -o $@ $(KERNEL_LINK) $(FORKU_LINK) $(SYMLIB_LINK)

libsnapshot.a: snapshot.o
	ar rcs $@ $^

forku_util: forku_util.c libforku.a libsnapshot.a
	$(CC) $(CFLAGS) -I$(SYMLIB_INCLUDE_DIR) $^ -o $@ $(KERNEL_LINK) $(FORKU_LINK) $(SNAPSHOT_LINK) $(SYMLIB_LINK)

malloc_spinner: spinner.c
	$(CC) $(CFLAGS) $^ -o $@

forku_monitord: forku_monitord.c libforku.a libsnapshot.a
	$(CC) $(CFLAGS) $(FUSE_FLAGS) -I$(SYMLIB_INCLUDE_DIR) $^ -o $@ $(KERNEL_LINK) $(FORKU_LINK) $(SNAPSHOT_LINK) $(SYMLIB_LINK)

run_forku_monitor: forku_monitord
	@mkdir -p sn
	./forku_monitord -f -s -d ./sn

clean:
	rm -rf *.o *.so *.s .*.d *.a core.* malloc_spinner forku_util forku_monitord
