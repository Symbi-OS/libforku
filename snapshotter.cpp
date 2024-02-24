#include "snapshotter.h"
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "json11.hpp"

struct pgd_to_p4ds_map {
  struct page_table_entry pgd;
  std::vector<struct page_table_entry> p4ds;
};

struct p4d_to_puds_map {
  struct page_table_entry p4d;
  std::vector<struct page_table_entry> puds;
};

struct pud_to_pmds_map {
  struct page_table_entry pud;
  std::vector<struct page_table_entry> pmds;
};

struct pmd_to_ptes_map {
  struct page_table_entry pmd;
  std::vector<struct page_table_entry> ptes;
};

static std::map<uint64_t, pgd_to_p4ds_map> pgd_map;  // pgd -> p4ds
static std::map<uint64_t, p4d_to_puds_map> p4d_map;  // p4d -> puds
static std::map<uint64_t, pud_to_pmds_map> pud_map;  // pud -> pmds
static std::map<uint64_t, pmd_to_ptes_map> pmd_map;  // pmd -> ptes

std::string to_hex_string(uint64_t value) {
  std::stringstream ss;
  ss << std::hex << value;
  return ss.str();
}

bool pte_exists_in_pmd_map(
                           uint64_t pmd_pfn,
                           struct page_table_entry& pte
                           ) {
  for (auto& entry : pmd_map[pmd_pfn].ptes) {
    if (entry.page_frame_number == pte.page_frame_number) {
      return true;
    }
  }

  return false;
}

json11::Json merge_json_objects(const json11::Json& obj1, const json11::Json& obj2) {
  json11::Json::object combined = obj1.object_items();
    
  for (const auto& item : obj2.object_items()) {
    combined[item.first] = item.second;
  }

  return combined;
}

json11::Json pte_to_json(struct page_table_entry& entry) {
  return json11::Json::object({
      { "pfn", to_hex_string(entry.page_frame_number) },
      { "present", (int)entry.present },
      { "read_write", (int)entry.read_write },
      { "user_supervisor", (int)entry.user_supervisor },
      { "page_write_through", (int)entry.page_write_through },
      { "page_cache_disabled", (int)entry.page_cache_disabled },
      { "accessed", (int)entry.accessed },
      { "dirty", (int)entry.dirty },
      { "page_access_type", (int)entry.page_access_type },
      { "global", (int)entry.global },
      { "protection_key", (int)entry.protection_key },
      { "execute_disable", (int)entry.execute_disable }
    });
}

json11::Json::array pmds_to_json(
                                 std::vector<struct page_table_entry>& pmds
                                 ) {
  json11::Json::array pmds_json_array;

  for (auto& pmd_entry : pmds) {
    uint64_t pmd_pfn = (uint64_t)pmd_entry.page_frame_number;
    auto& ptes = pmd_map[pmd_pfn].ptes;

    json11::Json::array ptes_json_array;
    for (auto& pte : ptes) {
      ptes_json_array.push_back(json11::Json::object(
                                                     pte_to_json(pte).object_items()
                                                     ));
    }

    json11::Json pmd_json_obj = json11::Json::object({
        { "ptes", ptes_json_array }
      });
    pmd_json_obj = merge_json_objects(pmd_json_obj, pte_to_json(pmd_entry));

    pmds_json_array.push_back(pmd_json_obj);
  }

  return pmds_json_array;
}

json11::Json::array puds_to_json(
                                 std::vector<struct page_table_entry>& puds
                                 ) {
  json11::Json::array puds_json_array;

  for (auto& pud_entry : puds) {
    uint64_t pud_pfn = (uint64_t)pud_entry.page_frame_number;
    auto& pmds = pud_map[pud_pfn].pmds;

    json11::Json pud_json_obj = json11::Json::object({
        { "pmds", pmds_to_json(pmds) }
      });
    pud_json_obj = merge_json_objects(pud_json_obj, pte_to_json(pud_entry));

    puds_json_array.push_back(pud_json_obj);
  }

  return puds_json_array;
}

json11::Json::array p4ds_to_json(
                                 std::vector<struct page_table_entry>& p4ds
                                 ) {
  json11::Json::array p4ds_json_array;

  for (auto& p4d_entry : p4ds) {
    uint64_t p4d_pfn = (uint64_t)p4d_entry.page_frame_number;
    auto& puds = p4d_map[p4d_pfn].puds;

    json11::Json p4d_json_obj = json11::Json::object({
        { "puds", puds_to_json(puds) }
      });
    p4d_json_obj = merge_json_objects(p4d_json_obj, pte_to_json(p4d_entry));

    p4ds_json_array.push_back(p4d_json_obj);
  }

  return p4ds_json_array;
}

json11::Json::array pgds_to_json() {
  json11::Json::array pgds_json_array;

  for (auto& [_, map] : pgd_map) {
    auto& p4ds = map.p4ds;

    json11::Json pgd_json_obj = json11::Json::object({
        { "p4ds", p4ds_to_json(p4ds) }
      });
    pgd_json_obj = merge_json_objects(pgd_json_obj, pte_to_json(map.pgd));

    pgds_json_array.push_back(pgd_json_obj);
  }

  return pgds_json_array;
}

void snapshot_task(struct task_struct* task, const char* filename) {
  pgd_map.clear();
  p4d_map.clear();
  pud_map.clear();
  pmd_map.clear();

  uint64_t pages_visited = 0;
  uint64_t pages_present = 0;
    
  void* vma = get_task_base_vma(task);
  while (vma) {
    uint64_t vm_start = get_task_vma_start(vma);
    uint64_t vm_end = get_task_vma_end(vma);
    break;
    
    for (uint64_t vmpage = vm_start; vmpage < vm_end; vmpage += PAGE_SIZE) { 
      struct page_table_entry* pte = get_pte_for_address(task, vmpage);
      if (!pte)
        continue;

      ++pages_visited;

      if (pte->present) {
        ++pages_present;

        struct page_table_entry pgd, p4d, pud, pmd, pte_leaf;
        fill_page_table_info_for_address(
                                         task,
                                         vmpage,
                                         &pgd, &p4d, &pud, &pmd,
                                         &pte_leaf
                                         );

        uint64_t pgd_pfn = (uint64_t)pgd.page_frame_number;
        uint64_t p4d_pfn = (uint64_t)p4d.page_frame_number;
        uint64_t pud_pfn = (uint64_t)pud.page_frame_number;
        uint64_t pmd_pfn = (uint64_t)pmd.page_frame_number;

        // Register the PGD
        if (pgd_map.find(pgd_pfn) == pgd_map.end()) {
          pgd_map[(uint64_t)pgd.page_frame_number] = { .pgd = pgd, .p4ds = {} };
        }
        if (p4d_map.find(p4d_pfn) == p4d_map.end()) {
          pgd_map[(uint64_t)pgd.page_frame_number].p4ds.push_back(p4d);
        }

        // Register the P4D
        if (p4d_map.find(p4d_pfn) == p4d_map.end()) {
          p4d_map[(uint64_t)p4d.page_frame_number] = { .p4d = p4d, .puds = {} };
        }
        if (pud_map.find(pud_pfn) == pud_map.end()) {
          p4d_map[(uint64_t)p4d.page_frame_number].puds.push_back(pud);
        }

        // Register the PUD
        if (pud_map.find(pud_pfn) == pud_map.end()) {
          pud_map[(uint64_t)pud.page_frame_number] = { .pud = pud, .pmds = {} };
        }
        if (pmd_map.find(pmd_pfn) == pmd_map.end()) {
          pud_map[(uint64_t)pud.page_frame_number].pmds.push_back(pmd);
        }

        // Register the PMD
        if (pmd_map.find(pmd_pfn) == pmd_map.end()) {
          pmd_map[(uint64_t)pmd.page_frame_number] = { .pmd = pmd, .ptes = {} };
        }
        if (!pte_exists_in_pmd_map(pmd_pfn, pte_leaf)) {
          pmd_map[(uint64_t)pmd.page_frame_number].ptes.push_back(pte_leaf);
        }
      }
    }

    vma = get_next_vma(vma);
  }

  printf("----- Visited %li Pages -----\n", pages_visited);
  printf("     Pages Present : %li\n\n", pages_present);

  // Export data to a file
  json11::Json root = json11::Json::object({
      { "pgds", pgds_to_json() },  // You'll need to replace this with the actual cr3 base address
    });
    
  std::string json_str = root.dump();
  std::ofstream log(filename);
  log << json_str;
}

void snapshot_pid(int pid, const char* filename) {
  struct task_struct* task = pid_to_task(pid);
  snapshot_task(task, filename);
}

