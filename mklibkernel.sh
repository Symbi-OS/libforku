#!/bin/bash

VMLINUX=~/Symbi-OS/linux/vmlinux
KERNELASM=kernel.s
OBJ=libkernel.o
LIB=libkernel.a

tmpfile=/tmp/$$_null.s
cat > $tmpfile <<EOF
.section .note.GNU-stack

EOF

blacklisted_symbols=(
  "malloc" "free" "calloc" "realloc"
  "strcpy" "strncpy" "strcat" "strncat" "strcmp" "strncmp" "strlen" "strchr" "strrchr" "strstr" "strtok" "sprintf" "sscanf" "atoi" "atol" "atof" "snprintf"
  "fopen" "fclose" "fread" "fwrite" "fprintf" "fscanf" "fgets" "fputs" "fseek" "ftell" "rewind" "ferror" "feof"
  "fork" "exec" "wait" "exit" "getpid" "getppid" "signal" "kill"
  "dlopen" "dlsym" "dlclose" "dlerror"
  "pthread_create" "pthread_join" "pthread_mutex_lock" "pthread_mutex_unlock" "pthread_cond_wait" "pthread_cond_signal"
  "socket" "connect" "bind" "listen" "accept" "send" "recv"
  "time" "localtime" "gmtime" "mktime" "strftime" "sleep"
  "mount" "umount" "dir_list" "__fentry__"
  "memset" "memcpy" "memmove" "memcmp" "memchr"
  "strerror" "strncpy" "strncat" "strcspn" "strspn" "strpbrk" "strtod" "strtol" "strtoul" "strxfrm"
  "isalpha" "isdigit" "isalnum" "islower" "isupper" "isspace" "ispunct" "isxdigit" "tolower" "toupper"
)

syms=""
nm $VMLINUX | while read val info sym; do
    for symbol in "${blacklisted_symbols[@]}"; do
        if [[ $sym == $symbol ]]; then
            continue 2
        fi
    done
    
    echo ".global $sym"
    echo ".set $sym,0x$val"
done > $KERNELASM

echo ".section .note.GNU-stack" >> $KERNELASM

gcc -static -c $KERNELASM -o $OBJ
ar rcs $LIB $OBJ

rm $KERNELASM
