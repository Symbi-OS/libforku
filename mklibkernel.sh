#!/bin/bash

VMLINUX=~/Symbi-OS/linux/vmlinux
KERNELASM=kernel.s
OBJ=libkernel.o
LIB=libkernel.a

tmpfile=/tmp/$$_null.s
cat > $tmpfile <<EOF
.section .note.GNU-stack

EOF


syms=""
nm $VMLINUX | while read val info sym; do
    if [[ $sym = abort ]]; then
        continue
    fi
  
    echo ".global $sym"
    echo ".set $sym,0x$val"
done > $KERNELASM

echo ".section .note.GNU-stack" >> $KERNELASM

gcc -static -c $KERNELASM -o $OBJ
ar rcs $LIB $OBJ

rm $KERNELASM
