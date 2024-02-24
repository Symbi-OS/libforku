#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <asm/ptrace.h>
#include <linux/slab.h> // kmem_cache_free

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Albert Slepak");
MODULE_DESCRIPTION("Forku Module Symbiote Library");
MODULE_VERSION("1.0");

struct vm_area_struct* get_task_base_vma(struct task_struct* task) {
  struct mm_struct* mm = task->mm;
  return mm->mmap;
}

struct vm_area_struct* get_next_vma(struct vm_area_struct* vma) {
  return vma->vm_next;
}

uint64_t get_task_vma_start(struct vm_area_struct* vma) {
  return vma->vm_start;
}

uint64_t get_task_vma_end(struct vm_area_struct* vma) {
  return vma->vm_end;
}

pte_t* get_pte_for_address(struct task_struct* task, uint64_t addr) {
  struct mm_struct* task_mm;
  pgd_t* pgd;
  p4d_t* p4d;
  pud_t* pud;
  pmd_t* pmd;
  pte_t* pte;

  task_mm = task->mm;

  pgd = pgd_offset(task_mm, addr);
  if (pgd_none(*pgd) || pgd_bad(*pgd))
    return NULL;

  p4d = p4d_offset(pgd, addr);
  if (p4d_none(*p4d) || p4d_bad(*p4d))
    return NULL;

  pud = pud_offset(p4d, addr);
  if (pud_none(*pud) || pud_bad(*pud))
    return NULL;

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd))
    return NULL;

  pte = pte_offset_kernel(pmd, addr);
  if (!pte)
    return NULL;

  return pte;
}

void fill_page_table_info_for_address(
                                      struct task_struct* task,
                                      uint64_t addr,
                                      uint64_t* out_pgd,
                                      uint64_t* out_p4d,
                                      uint64_t* out_pud,
                                      uint64_t* out_pmd,
                                      uint64_t* out_pte
                                      ) {
  struct mm_struct* task_mm;
  pgd_t* pgd;
  p4d_t* p4d;
  pud_t* pud;
  pmd_t* pmd;
  pte_t* pte;

  task_mm = task->mm;

  pgd = pgd_offset(task_mm, addr);
  if (pgd_none(*pgd) || pgd_bad(*pgd))
    return;

  p4d = p4d_offset(pgd, addr);
  if (p4d_none(*p4d) || p4d_bad(*p4d))
    return;

  pud = pud_offset(p4d, addr);
  if (pud_none(*pud) || pud_bad(*pud))
    return;

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd))
    return;

  pte = pte_offset_kernel(pmd, addr);
  if (!pte)
    return;

  // Write the results into output variables
  *out_pgd = pgd_val(*pgd);
  *out_p4d = p4d_val(*p4d);
  *out_pud = pud_val(*pud);
  *out_pmd = pmd_val(*pmd);
  *out_pte = pte_val(*pte);
}

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

extern struct kmem_cache *task_struct_cachep;

void destroy_task_struct(struct task_struct* task) {
  kmem_cache_free(task_struct_cachep, task);
}

extern __latent_entropy struct task_struct *copy_process(
                                                         struct pid *pid,
                                                         int trace,
                                                         int node,
                                                         struct kernel_clone_args *args
                                                         );

extern struct task_struct *forku_copy_process(
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

  asm volatile ("swapgs" ::: "memory"); // switch to kernel gs
  asm volatile ("mov %%rsp, %%gs:0x6014" ::: "memory"); // save current SP into scratch space
  asm volatile ("mov %%gs:0x17b90, %%rsp" ::: "memory"); // switch onto current_top_of_stack
  
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
  //forked_task = copy_process(NULL, 0, NUMA_NO_NODE, &args);
  forked_task = forku_copy_process(NULL, 0, NUMA_NO_NODE, &args);
  
  // Swap the current task back to the original task of the forku_util process
  this_cpu_write(current_task, original_task);
  if (!static_branch_likely(&switch_to_cond_stibp)) {
    asm volatile("nop");
  }
    
  printk("forked_task       : 0x%llx\n", (uint64_t)forked_task);
  printk("impersonated pid  : %i\n", impersonated_pid);
  printk("current->pid      : %i\n", current->pid);
  printk("\n");

  
  asm volatile ("mov %%gs:0x6014, %%rsp" ::: "memory"); // restore saved stack pointer
  asm volatile ("swapgs"); // switch back to user gs
  
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

void kill_forku_task(struct task_struct* task) {
  (void)task;
  // NOT YET IMPLEMENTED
}

void kill_forku_process(int pid) {
  void* target_task_struct;
  
  target_task_struct = pid_to_task(pid);
  if (!target_task_struct) {
    return;
  }

  kill_forku_task(target_task_struct);
}

