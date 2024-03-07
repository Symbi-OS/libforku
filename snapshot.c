#include "snapshot.h"
#include <stdio.h>

void snapshot_task(struct task_struct *task, int target_pid, const char* filename, size_t *out_total_pages, size_t *out_present_pages) {
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  struct pte_struct pgd, p4d, pud, pmd, pte;
  uint64_t addr, pages_total = 0, pages_present = 0, vma_pages;
  FILE *xml_file;

  if (!filename)
    filename = "/dev/null";
  
  xml_file = fopen(filename, "w");
  if (!xml_file) {
    fprintf(stderr, "Failed to open file\n");
    return;
  }
  
  if (!task || !(mm = get_task_mm_struct(task))) {
    fprintf(stderr, "Invalid task or mm\n");
    return;
  }

  fprintf(xml_file, "<snapshot pid=\"%d\">\n", target_pid);
  
  acquire_mm_lock(mm);
  for (vma = get_base_vma(mm); vma; vma = get_next_vma(vma)) {
    //printf("VMA: 0x%lx - 0x%lx ", get_vma_start(vma), get_vma_end(vma));
    vma_pages = 0;

    fprintf(xml_file, "  <vma start=\"0x%lx\" end=\"0x%lx\">\n", get_vma_start(vma), get_vma_end(vma));
    
    for (addr = get_vma_start(vma); addr < get_vma_end(vma); addr += PAGE_SIZE) {
      pgd.value = 0;
      p4d.value = 0;
      pud.value = 0;
      pmd.value = 0;
      pte.value = 0;
    
      get_page_table_info_for_address(mm, addr, &pgd, &p4d, &pud, &pmd, &pte);
      if (!pgd.present || !p4d.present || !pud.present || !pmd.present)
        continue;
      
      ++pages_total;
      ++vma_pages;
      
      if (pte.present)
        ++pages_present;

      fprintf(xml_file,
              "    <page addr=\"0x%lx\">\n"
              "      <present>%d</present>\n"
              "      <read_write>%d</read_write>\n"
              "      <user_supervisor>%d</user_supervisor>\n"
              "      <page_write_through>%d</page_write_through>\n"
              "      <page_cache_disabled>%d</page_cache_disabled>\n"
              "      <accessed>%d</accessed>\n"
              "      <dirty>%d</dirty>\n"
              "      <page_access_type>%d</page_access_type>\n"
              "      <global>%d</global>\n"
              "      <page_frame_number>%lu</page_frame_number>\n"
              "      <protection_key>%d</protection_key>\n"
              "      <execute_disable>%d</execute_disable>\n"
              "    </page>\n",
              addr, pte.present, pte.read_write, pte.user_supervisor, pte.page_write_through,
              pte.page_cache_disabled, pte.accessed, pte.dirty, pte.page_access_type, pte.global,
              (uint64_t)pte.page_frame_number, pte.protection_key, pte.execute_disable);
    }

    //printf("    pages in vma: %li\n", vma_pages);

    fprintf(xml_file, "    <pagesInVMA>%li</pagesInVMA>\n", vma_pages);
    fprintf(xml_file, "  </vma>\n");
  }
  release_mm_lock(mm);

  fprintf(xml_file, "  <summary pagesPresent=\"%li\" totalPages=\"%li\"/>\n", pages_present, pages_total);
  fprintf(xml_file, "</snapshot>\n");

  printf("Pages present : %li\n", pages_present);
  printf("Total pages   : %li\n", pages_total);
  printf("Wrote results to %s\n", filename);
  printf("\n");
  
  fclose(xml_file);

  if (out_total_pages)
    *out_total_pages = pages_total;

  if (out_present_pages)
    *out_present_pages = pages_present;
}

void snapshot_pid(int target_pid, const char* filename) {
  struct task_struct *task = pid_to_task(target_pid);
  snapshot_task(task, target_pid, filename, NULL, NULL);
}

