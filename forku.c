#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <asm/ptrace.h>
#include <linux/slab.h> // kmem_cache_free
#include <linux/fs.h> // For struct files_struct and other file related structures
#include <linux/file.h> // For fget, fput, etc.
#include <linux/fdtable.h> // For fdtable

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Albert Slepak");
MODULE_DESCRIPTION("Forku Module Symbiote Library");
MODULE_VERSION("1.0");

struct task_struct *get_current_task(void) {
  return current;
}

struct task_struct *pid_to_task(__kernel_pid_t pid) {
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

extern struct task_struct *forku_copy_process(struct kernel_clone_args *args);
extern struct task_struct *forku_populate_process(struct task_struct *p, struct task_struct *foster_parent, struct kernel_clone_args *args);

int *read_tid_ptr(struct task_struct* task) {
  uint64_t fsbase, tls_entry;
  uint64_t* tls_entry_ptr;
  int* tid_ptr;

  fsbase = task->thread.fsbase;
  tls_entry_ptr = (uint64_t*)(fsbase + 0x10);
  tls_entry = *tls_entry_ptr;
  tid_ptr = (int*)(tls_entry + 0x2d0);

  return tid_ptr;
}

static int copy_std_fds(struct task_struct *src, struct task_struct *dst) {
  struct fdtable *src_fdt, *dst_fdt;
  struct file *file;
  int fd, ret = 0;

  if (!src || !dst)
    return -EINVAL;

  rcu_read_lock();
  src_fdt = files_fdtable(src->files);
  dst_fdt = files_fdtable(dst->files);

  // Loop over the file descriptors 1 and 2 (stdout and stderr)
  for (fd = 0; fd <= 2; fd++) {
    file = rcu_dereference_check_fdtable(src->files, src_fdt->fd[fd]);
    if (file) {
      get_file(file); // Increment the reference count of the file

      spin_lock(&dst->files->file_lock);
      // Check if the destination already has a file for this fd
      if (dst_fdt->fd[fd]) {
        // Close the existing file in the destination task
        filp_close(rcu_dereference_protected(dst_fdt->fd[fd], true), dst->files);
      }
      // Assign the file from the source to the destination
      rcu_assign_pointer(dst_fdt->fd[fd], file);
      spin_unlock(&dst->files->file_lock);
    }
  }

  rcu_read_unlock();
  return ret;
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
    .flags      = 0x1200000 | CLONE_PARENT,
    .pidfd      = NULL, // if you want a pidfd, you need to allocate it
    .child_tid  = NULL, // child's TID in the child memory
    .parent_tid = NULL, // child's TID in the parent memory
    .exit_signal = SIGCHLD,
  };

  //args.child_tid  = read_tid_ptr(current);
  
  original_task = current;
  printk("[FORKU]\n");
  printk("current->pid      : %i\n", current->pid);

  preempt_disable();
  local_irq_disable();
  
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
  forked_task = forku_copy_process(&args);
  
  // Swap the current task back to the original task of the forku_util process
  this_cpu_write(current_task, original_task);
  if (!static_branch_likely(&switch_to_cond_stibp)) {
    asm volatile("nop");
  }

  local_irq_enable();
  preempt_enable();
    
  printk("forked_task       : 0x%llx\n", (uint64_t)forked_task);
  printk("impersonated pid  : %i\n", impersonated_pid);
  printk("current->pid      : %i\n", current->pid);
  printk("\n");

  return forked_task;
}
#pragma GCC diagnostic pop

struct task_struct *forku_pid(int pid) {
  void* target_task_struct;

  target_task_struct = pid_to_task(pid);
  if (!target_task_struct) {
    return NULL;
  }

  return forku_task(target_task_struct);
}

void forku_populate_task(struct task_struct *task, struct task_struct *foster_parent) {
  copy_std_fds(foster_parent, task);
}

void forku_schedule_task(struct task_struct *task) {
  wake_up_new_task(task);
}

extern struct kmem_cache *task_struct_cachep;

void forku_free_task(struct task_struct *task) {
  kmem_cache_free(task_struct_cachep, task);
}

struct mm_struct *get_task_mm_struct(struct task_struct *task) {
  return task->mm;
}

struct vm_area_struct *get_base_vma(struct mm_struct *mm) {
  return mm->mmap;
}

struct vm_area_struct *get_next_vma(struct vm_area_struct *vma) {
  return vma->vm_next;
}

uint64_t get_vma_start(struct vm_area_struct *vma) {
  return vma->vm_start;
}

uint64_t get_vma_end(struct vm_area_struct *vma) {
  return vma->vm_end;
}

void unmap_pte(pte_t *pte) {
  pte_unmap(pte);
}

void acquire_mm_lock(struct mm_struct *mm) {
  down_read(&mm->mmap_lock);
}

void release_mm_lock(struct mm_struct *mm) {
  up_read(&mm->mmap_lock);
}

void get_page_table_info_for_address(
                                     struct mm_struct *mm,
                                     uint64_t addr,
                                     uint64_t *out_pgd,
                                     uint64_t *out_p4d,
                                     uint64_t *out_pud,
                                     uint64_t *out_pmd,
                                     uint64_t *out_pte
                                     ) {
  pgd_t* pgd;
  p4d_t* p4d;
  pud_t* pud;
  pmd_t* pmd;
  pte_t* pte;

  pgd = pgd_offset(mm, addr);
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

  pte = pte_offset_map(pmd, addr);
  if (!pte)
    return;

  // Write the results into output variables
  *out_pgd = pgd_val(*pgd);
  *out_p4d = p4d_val(*p4d);
  *out_pud = pud_val(*pud);
  *out_pmd = pmd_val(*pmd);
  *out_pte = pte_val(*pte);

  pte_unmap(pte);
}

