#include <stdio.h>
#include <stdlib.h>
#include "snapshot.h"

int main(int argc, char** argv) {
    void* forked_task = NULL;
    int current_pid = getpid();
    int target_pid = -1;
    char snapshot_name[256] = { 0 };

    if (argc != 2) {
        printf("Usage: ./test <pid_to_clone>\n");
        exit(0);
    }

    sym_elevate();
    
    target_pid = atoi(argv[1]);
    snprintf(snapshot_name, sizeof(snapshot_name), "snapshot_%d_parent.xml", target_pid);
    
    printf("Current PID: %i\n", current_pid);
    printf("Target  PID: %i\n", target_pid);

    // First create a snapshot of the target task as a parent
    snapshot_pid(target_pid, snapshot_name);
    
    // Partially fork the process
    forked_task = forku_pid(target_pid);

    // Snapshot the cloned task
    snprintf(snapshot_name, sizeof(snapshot_name), "snapshot_%d_child.xml", target_pid);
    snapshot_task(forked_task, target_pid, snapshot_name);
    
    // Free the cloned task_struct because for now we
    // don't have a way to manage these forked tasks.
    forku_free_task(forked_task);

    sym_lower();

    if (!forked_task) {
        printf("[-] Failed to fork the target task\n");
        return -1;
    }

    printf("Successfully forked the task!\ntask_struct: %p\n", forked_task);
    return 0;
}
