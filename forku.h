#ifndef FORKU_H
#define FORKU_H
#include <stdint.h>

#define PAGE_SIZE 0x1000

// Forward declarations
struct task_struct;
struct mm_struct;
struct vm_area_struct;
struct pte_struct;

// Misc.
void forku_free_task(struct task_struct *task);
struct task_struct *get_current_task();

// Forku functions
struct task_struct *pid_to_task(int pid);
struct task_struct *forku_task(struct task_struct* target_task);
struct task_struct *forku_pid(int pid);
struct task_struct *forku_create_runnable_from_snapshot(struct task_struct *target_task, struct task_struct *foster_parent);
int copy_task_fd(struct task_struct *dst, struct task_struct *src, int fd);
void forku_schedule_task(struct task_struct *task);

// Page table functions
struct mm_struct *get_task_mm_struct(struct task_struct *task);
struct vm_area_struct *get_base_vma(struct mm_struct *mm);
struct vm_area_struct *get_next_vma(struct vm_area_struct *vma);
uint64_t get_vma_start(struct vm_area_struct *vma);
uint64_t get_vma_end(struct vm_area_struct *vma);
void unmap_pte(struct pte_struct *pte);
void acquire_mm_lock(struct mm_struct *mm);
void release_mm_lock(struct mm_struct *mm);

void get_page_table_info_for_address(
                                     struct mm_struct *mm,
                                     uint64_t addr,
                                     struct pte_struct *out_pgd,
                                     struct pte_struct *out_p4d,
                                     struct pte_struct *out_pud,
                                     struct pte_struct *out_pmd,
                                     struct pte_struct *out_pte
                                     );

struct pte_struct {
    union
    {
        struct
        {
            uint64_t present                : 1;    // Must be 1, region invalid if 0.
            uint64_t read_write             : 1;    // If 0, writes not allowed.
            uint64_t user_supervisor        : 1;    // If 0, user-mode accesses not allowed.
            uint64_t page_write_through     : 1;    // Determines the memory type used to access the memory.
            uint64_t page_cache_disabled    : 1;    // Determines the memory type used to access the memory.
            uint64_t accessed               : 1;    // If 0, this entry has not been used for translation.
            uint64_t dirty                  : 1;    // If 0, the memory backing this page has not been written to.
            uint64_t page_access_type       : 1;    // Determines the memory type used to access the memory.
            uint64_t global                 : 1;    // If 1 and the PGE bit of CR4 is set, translations are global.
            uint64_t ignored2               : 3;
            uint64_t page_frame_number      : 36;   // The page frame number of the backing physical page.
            uint64_t reserved               : 4;
            uint64_t ignored3               : 7;
            uint64_t protection_key         : 4;    // If the PKE bit of CR4 is set, determines the protection key.
            uint64_t execute_disable        : 1;    // If 1, instruction fetches not allowed.
        };
        uint64_t value;
    };
} __attribute__((packed));

#endif

