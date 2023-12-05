#include <stdio.h>
#include <stdlib.h>
#include "forku.h"
#include <LINF/sym_all.h>

int main(int argc, char** argv) {
    void* forked_task = NULL;
    int current_pid = getpid();
    int target_pid = -1;

    if (argc != 2) {
        printf("Usage: ./test <pid_to_clone>\n");
        exit(0);
    }

    target_pid= atoi(argv[1]);
	
    printf("Current PID: %i\n", current_pid);
    printf("Target  PID: %i\n", target_pid);
        
    sym_elevate();
    forked_task = forku_pid(target_pid);
    sym_lower();

    if (!forked_task) {
        printf("[-] Failed to fork the target task\n");
        return -1;
    }

    printf("Successfully forked the task!\ntask_struct: %p\n", forked_task);
    return 0;
}
