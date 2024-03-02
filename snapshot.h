#ifndef SNAPSHOT_H
#define SNAPSHOT_H
#include <stdlib.h>
#include "forku.h"
#include <LINF/sym_all.h>

void snapshot_task(struct task_struct *task, int target_pid, const char* filename);

void snapshot_pid(int target_pid, const char* filename);

#endif

