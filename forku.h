#ifndef FORKU_H
#define FORKU_H

// Forward declaration
struct task_struct;


struct task_struct* pid_to_task(int pid);

struct task_struct* forku_task(struct task_struct* target_task);

struct task_struct* forku_pid(int pid);

#endif
