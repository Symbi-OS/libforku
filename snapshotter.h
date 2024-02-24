#ifndef SNAPSHOTTER_H
#define SNAPSHOTTER_H
extern "C" {
    #include "forku.h"
}

void snapshot_task(struct task_struct* task, const char* filename);

void snapshot_pid(int pid, const char* filename);

#endif

