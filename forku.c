#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Albert Slepak");
MODULE_DESCRIPTION("Forku Module Symbiote Library");
MODULE_VERSION("1.0");

struct task_struct* pid_to_task(__kernel_pid_t pid) {
    // *Note* try 'static struct task_struct *find_process_by_pid(pid_t pid)'

    struct pid* pid_struct;
    struct task_struct* task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    return task;
}

extern __latent_entropy struct task_struct *copy_process(
    struct pid *pid,
    int trace,
    int node,
    struct kernel_clone_args *args
);

int* read_tid_ptr(struct task_struct* task) {
  uint64_t fsbase, tls_entry;
  uint64_t* tls_entry_ptr;
  int* tid_ptr;

  fsbase = task->thread.fsbase;
  tls_entry_ptr = (uint64_t*)(fsbase + 0x10);
  tls_entry = *tls_entry_ptr;
  tid_ptr = (int*)(tls_entry + 0x2d0);

  return tid_ptr;
}

#pragma GCC diagnostic error "-Wdeclaration-after-statement"
struct task_struct* forku_task(struct task_struct* target_task) {
    /*
        Outline:
            original_task = current
            current = target_task
            *syscall*
            current = original_task
    */
    struct task_struct*  original_task;
    struct task_struct*  forked_task;
    int                  impersonated_pid;

    struct kernel_clone_args args = {
        .flags      = 0x1200000,
        .pidfd      = NULL, // if you want a pidfd, you need to allocate it
        .child_tid  = NULL, // child's TID in the child memory
        .parent_tid = NULL, // child's TID in the parent memory
        .exit_signal = SIGCHLD,
    };

    //args.child_tid  = read_tid_ptr(current);

    original_task = current;
    printk("current->pid      : %i\n", current->pid);

    // Impersonate the target task, for some reason abstracting this
    // away into its own function causes it to not work anymore.
    this_cpu_write(current_task, target_task);

    // The following if statement makes the CPU do something that appears like
    // a flush of hidden segment register caches and necessary in order to
    // update the current task in the per-cpu data structure.
    if (!static_branch_likely(&switch_to_cond_stibp)) {
      asm volatile("nop");
    }

    impersonated_pid = current->pid;
    forked_task = copy_process(NULL, 0, NUMA_NO_NODE, &args);
	
    this_cpu_write(current_task, original_task);
    if (!static_branch_likely(&switch_to_cond_stibp)) {
      asm volatile("nop");
    }
    
    printk("forked_task       : 0x%llx\n", (uint64_t)forked_task);
    printk("impersonated pid  : %i\n", impersonated_pid);
    printk("current->pid      : %i\n", current->pid);
    printk("\n");

    return forked_task;
}
#pragma GCC diagnostic pop

struct task_struct* forku_pid(int pid) {
    void* target_task_struct;

    target_task_struct = pid_to_task(pid);
    if (!target_task_struct) {
        return NULL;
    }

    return forku_task(target_task_struct);
}

