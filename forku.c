#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/file.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/switch_to.h>
#include <linux/printk.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/pkru.h>
#include <asm/fpu/internal.h>
#include <asm/mmu_context.h>
#include <asm/prctl.h>
#include <asm/desc.h>
#include <asm/proto.h>
#include <asm/ia32.h>
#include <asm/debugreg.h>
#include <asm/switch_to.h>
#include <asm/resctrl.h>
#include <asm/unistd.h>

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
    int test_pid;
    unsigned long child_tid_ptr;
    struct kernel_clone_args args = {
        .flags      = 0x1200000,
        .pidfd      = NULL, // if you want a pidfd, you need to allocate it
        .child_tid  = NULL, // child's TID in the child memory
        .parent_tid = NULL, // child's TID in the parent memory
        .exit_signal = SIGCHLD,
    };

    asm volatile("mov %%fs:0x0, %0" : "=r"(child_tid_ptr));
    child_tid_ptr += 0x2d0;
    args.child_tid  = (int*)child_tid_ptr;

    printk("ctid: 0x%lx\n", child_tid_ptr);

    // Disable preemption and local interrupts
    local_irq_disable();
    preempt_disable();

    original_task = current;

    printk("current->pid    : %i\n", current->pid);

    this_cpu_write(current_task, target_task);
    if (!static_branch_likely(&switch_to_cond_stibp)) {
        asm volatile("nop");
    }

    test_pid = current->pid;

    forked_task = copy_process(NULL, 0, NUMA_NO_NODE, &args);

    this_cpu_write(current_task, original_task);
    if (!static_branch_likely(&switch_to_cond_stibp)) {
        asm volatile("nop");
    }

    // Enable preemption and local interrupts
    preempt_enable();
    local_irq_enable();

    printk("forked_task     : 0x%llx\n", (uint64_t)forked_task);
    printk("test_pid        : %i\n", test_pid);
    printk("current->pid    : %i\n", current->pid);
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

int init_module(void) {
    return 0;
}

void cleanup_module(void) {
}
