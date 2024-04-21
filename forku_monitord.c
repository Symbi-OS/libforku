#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include "snapshot.h"

struct snapshot {
  int                pid;
  char               *name;
  struct task_struct *task;
};

struct pid_entry {
  int pid;
  struct snapshot *snapshots; // Array of snapshots
  size_t snapshot_count;      // Number of snapshots
  size_t capacity;            // Capacity of the snapshots array
};

struct pid_list {
  struct pid_entry *entries;   // Pointer to the array of PIDs
  size_t count;                // Current number of PIDs
  size_t capacity;             // Current capacity of the array
};

// Global array of registered pids
struct pid_list g_pids = { .entries = NULL, .count = 0, .capacity = 0 };

int pid_registered(int pid) {
  for(size_t i = 0; i < g_pids.count; ++i) {
    if (g_pids.entries[i].pid == pid)
      return 1;
  }

  return 0;
}

struct pid_entry *get_pid_entry(int pid) {
  for (size_t i = 0; i < g_pids.count; i++) {
    if (g_pids.entries[i].pid == pid)
      return &g_pids.entries[i];
  }

  return NULL;
}

struct snapshot *get_snapshot(int pid, const char* name) {
  if (!pid_registered(pid))
    return NULL;

  struct pid_entry *entry = get_pid_entry(pid);
  if (!entry)
    return NULL;

  for (size_t i = 0; i < entry->snapshot_count; i++) {
    if (strcmp(entry->snapshots[i].name, name) == 0)
      return &entry->snapshots[i];
  }

  return NULL;
}

int snapshot_exists(int pid, const char* name) {
  struct snapshot *sn = get_snapshot(pid, name);
  return (sn != NULL);
}

int register_pid(int pid) {
  if (pid_registered(pid))
    return 0;

  // Check if we need to expand the array
  if (g_pids.count == g_pids.capacity) {
    size_t new_capacity = g_pids.capacity == 0 ? 4 : g_pids.capacity * 2;
    struct pid_entry *new_entries = realloc(g_pids.entries, new_capacity * sizeof(struct pid_entry));
    if (!new_entries) {
      perror("Failed to realloc PID entries array");
      return 0;
    }

    g_pids.entries = new_entries;
    g_pids.capacity = new_capacity;
  }

  // Add a new PID entry
  struct pid_entry entry;
  memset(&entry, 0, sizeof(struct pid_entry));
  entry.pid = pid;
  
  g_pids.entries[g_pids.count++] = entry;

  return 1;
}

int register_snapshot(int pid, void* task, const char* name) {
  if (!pid_registered(pid))
    return 0;

  struct pid_entry *entry = get_pid_entry(pid);
  
  // Check if we need to expand the array
  if (entry->snapshot_count == entry->capacity) {
    size_t new_capacity = entry->capacity == 0 ? 4 : entry->capacity * 2;
    struct snapshot *new_snapshots = realloc(entry->snapshots, new_capacity * sizeof(struct snapshot));
    if (!new_snapshots) {
      perror("Failed to realloc snapshots array");
      return 0;
    }

    entry->snapshots = new_snapshots;
    entry->capacity = new_capacity;
  }

  // Add a new snapshot entry
  struct snapshot sn;
  memset(&sn, 0, sizeof(struct snapshot));
  sn.pid = pid;
  sn.task = task;

  sn.name = malloc(strlen(name) + 1);
  strcpy(sn.name, name);
  
  entry->snapshots[entry->snapshot_count++] = sn;
  return 1;
}

struct task_struct* take_snapshot(int target_pid) {
  struct task_struct *forked_task = NULL;

  sym_elevate();
  forked_task = forku_pid(target_pid);
  sym_lower();

  return forked_task;
}

void launch_snapshot(struct snapshot *sn, int foster_parent_pid) {
  // Perform the forku_schedule_task operation on the snapshot
  struct task_struct *runnable_task;
  struct task_struct *foster_parent;

  sym_elevate();
  runnable_task = forku_task(sn->task);
  foster_parent = pid_to_task(foster_parent_pid);
  
  forku_populate_task(runnable_task, foster_parent);

  forku_schedule_task(runnable_task);
  sym_lower();
}

void free_snapshot_task(struct task_struct *task) {
  sym_elevate();
  forku_free_task(task);
  sym_lower();
}

void add_dir(const char *dir_name) {
  printf("Request to add directory: %s\n", dir_name);
}

int is_dir(const char *path) {
  (void)path; // Mark unused parameter
  printf("Checking if a path is a directory\n");
  return 0; // Assuming not a directory for simplicity
}

void add_file(const char *filename) {
  printf("Request to add file: %s\n", filename);
}

int is_file(const char *path) {
  (void)path; // Mark unused parameter
  printf("Checking if a path is a file\n");
  return 0; // Assuming not a file for simplicity
}

void write_to_file(const char *path, const char *new_content) {
  printf("Request to write to file: %s, Content: %s\n", path, new_content);
}

static int do_getattr(const char *path, struct stat *st) {
  memset(st, 0, sizeof(struct stat));

  // Handling the root directory
  if (strcmp(path, "/") == 0) {
    st->st_mode = S_IFDIR | 0555;
    st->st_nlink = 2;
  } else {
    // Attempt to interpret the path as either a PID directory or a snapshot file
    char *path_copy = strdup(path);
    char *parent_dir = dirname(path_copy);
    char *last_component = basename((char*)path);

    // Check if the parent directory is root (indicating a PID directory)
    if (strcmp(parent_dir, "/") == 0) {
      long pid = strtol(last_component, NULL, 10);

      if (pid > 0 && pid_registered(pid)) {
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2; // Mimic as a directory for registered PIDs
        free(path_copy);
        return 0;
      }
    } else {
      // Handle snapshot files within a PID directory
      long pid = strtol(parent_dir + 1, NULL, 10); // Convert parent directory name to PID

      if (pid > 0 && pid_registered(pid)) {
        if (snapshot_exists(pid, last_component)) {
          // Mimic as a regular file for existing snapshots
          st->st_mode = S_IFREG | 0444; // Read-only for simplicity
          st->st_nlink = 1; // Regular file
          st->st_size = 4096;
          free(path_copy);
          return 0;
        }
      }
    }

    free(path_copy);
    return -ENOENT; // Path does not correspond to a valid PID or snapshot
  }
  
  return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  (void)offset; // Unused parameter
  (void)fi; // Unused parameter

  if (strcmp(path, "/") == 0) {
    // Listing PIDs as directories
    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);

    for (size_t i = 0; i < g_pids.count; ++i) {
      char pid_dir[32];
      sprintf(pid_dir, "%d", g_pids.entries[i].pid);
      filler(buffer, pid_dir, NULL, 0);
    }
  } else {
    // Attempt to list snapshots within a PID directory
    long pid = strtol(path + 1, NULL, 10);
    if (pid > 0 && pid_registered(pid)) {
      struct pid_entry *entry = get_pid_entry(pid);

      if (entry) {
        filler(buffer, ".", NULL, 0);
        filler(buffer, "..", NULL, 0);

        for (size_t i = 0; i < entry->snapshot_count; ++i) {
          filler(buffer, entry->snapshots[i].name, NULL, 0);
        }

        return 0; // Success
      }
    }
    
    return -ENOENT; // No such file or directory
  }
  
  return 0; // Successy
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)fi;
  
  // Split the path into the PID directory and the snapshot name
  char *path_copy = strdup(path);
  char *parent_dir = dirname(path_copy);
  char *snapshot_name = basename((char*)path);

  // Convert parent directory name to PID
  long pid = strtol(parent_dir + 1, NULL, 10);
  if (pid <= 0) {
    free(path_copy);
    return -EINVAL; // Invalid argument if PID is not positive
  }

  // Check if PID is registered and get the snapshot struct
  if (!pid_registered(pid)) {
    free(path_copy);
    return -ENOENT; // No such file or directory if PID is not registered
  }

  struct snapshot *sn = get_snapshot(pid, snapshot_name);
  if (sn == NULL) {
    free(path_copy);
    return -ENOENT; // No such file or directory if snapshot is not found
  }

  free(path_copy);
  
  size_t total_pages = 0, present_pages = 0;
  
  // Simply walk through VMAs without writing them to a file
  // and print the results to stdout.
  sym_elevate();
  snapshot_task(sn->task, (int)pid, NULL, &total_pages, &present_pages); 
  sym_lower();

  // Prepare the message.
  char message[512] = { 0 };
  int message_len = snprintf(message, sizeof(message),
                             "Total pages    : %zu\n"
                             "Present pages  : %zu\n",
                             total_pages, present_pages);

  // Check if offset is beyond the end of the message.
  if (offset >= message_len) {
    return 0; // Nothing more to read.
  }

  // Calculate how much data we can copy.
  size_t available = message_len - offset; // How much data is available to read.
  size_t bytes_to_copy = (size < available) ? size : available;

  // Copy the portion of the message to the buffer.
  memcpy(buffer, message + offset, bytes_to_copy);

  return bytes_to_copy; // Return the number of bytes copied.
}

static int do_mkdir(const char *path, mode_t mode) {
  (void)mode; // Mark unused parameter

  // Attempt to convert the path (excluding the leading '/') to a long integer.
  char *endptr;
  long pid = strtol(path + 1, &endptr, 10); // Base 10 conversion

  // Validate conversion.
  // Check if conversion stopped at the first character or if there were any non-numeric characters.
  if (endptr == path + 1 || *endptr != '\0') {
    printf("Error: Path is not a valid integer.\n");
    return -EINVAL; // Invalid argument error
  }

  // Check if the PID is within a valid range (assuming PID > 0).
  if (pid <= 0) {
    printf("Error: PID must be a positive integer.\n");
    return -EINVAL;
  }

  // Add the PID to our array.
  if (!register_pid((int)pid))
    return -EINVAL;

  return 0; // Return success
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev) {
  (void)mode; // Mark unused parameter
  (void)rdev; // Mark unused parameter

  // Split the path into PID and snapshot name
  char *path_copy = strdup(path);
  char *dir = dirname(path_copy);
  char *base = basename((char*)path);

  if (strcmp(dir, "/") == 0) {
    free(path_copy);
    printf("mknod called at root, which is not supported for snapshot creation.\n");
    return -EPERM; // Operation not permitted
  }

  long pid = strtol(dir + 1, NULL, 10); // Convert PID from string to long
  if (pid > 0 && pid_registered(pid)) {
    if (!snapshot_exists(pid, base)) {
      // Here we actually take a snapshot with libforku
      struct task_struct *task = take_snapshot(pid);
      
      if (register_snapshot(pid, task, base)) {
        free(path_copy);
        return 0; // Success
      } else {
        free_snapshot_task(task);
        free(path_copy);
        return -EIO; // I/O error
      }
    } else {
      free(path_copy);
      printf("Snapshot %s for PID %ld already exists.\n", base, pid);
      return -EEXIST; // File exists
    }
  }

  free(path_copy);
  return 0; // Return success
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)fi; // The fi parameter is unused for now.
  (void)size;
  (void)offset;
  (void)buffer;
  
  // Split the path into the PID directory and the snapshot name
  char *path_copy = strdup(path);
  char *parent_dir = dirname(path_copy);
  char *snapshot_name = basename((char*)path);

  // Convert parent directory name to PID
  long pid = strtol(parent_dir + 1, NULL, 10);
  if (pid <= 0) {
    free(path_copy);
    return -EINVAL; // Invalid argument if PID is not positive
  }

  // Check if PID is registered and get the snapshot struct
  if (!pid_registered(pid)) {
    free(path_copy);
    return -ENOENT; // No such file or directory if PID is not registered
  }

  struct snapshot *sn = get_snapshot(pid, snapshot_name);
  if (sn == NULL) {
    free(path_copy);
    return -ENOENT; // No such file or directory if snapshot is not found
  }

  // Ensure buffer is null-terminated by making a copy
  char *buffer_copy = strndup(buffer, size);
  if (!buffer_copy) {
    return -ENOMEM; // Return out of memory error
  }

  // Now we need to convert the buffer of user content that is
  // being written to a target foster parent process pid.
  char *endptr;
  errno = 0; // Clear errno before conversion
  long foster_parent_pid = strtol(buffer_copy, &endptr, 10);

  // Check if conversion was successful
  if (errno == ERANGE || foster_parent_pid == 0) {
    free(buffer_copy);
    return -EINVAL; // Conversion error or range error
  }

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  printf("%ld.%09ld\n", ts.tv_sec, ts.tv_nsec);

  // Perform the forku_schedule_task operation on the snapshot
  launch_snapshot(sn, foster_parent_pid);
  
  free(buffer_copy);
  free(path_copy);
  return size;
}

static int do_utimens(const char *path, const struct timespec ts[2]) {
  // This is a simplified implementation. You might want to store these times in your data structure.
  (void)path; // Mark unused parameter
  (void)ts;   // Mark unused parameter

  // Return 0 to indicate success.
  return 0;
}

void fuse_shutdown(void* private_data) {
  (void)private_data;

  sym_elevate();

  for (size_t i = 0; i < g_pids.count; i++) {
    struct pid_entry *entry = &g_pids.entries[i];

    for (size_t snidx = 0; snidx < entry->snapshot_count; snidx++) {
      struct snapshot *sn = &entry->snapshots[snidx];
      forku_free_task(sn->task);
      printf("Freed snapshot task 0x%lx\n", (uint64_t)sn->task);
    }
  }

  sym_lower();
}

static struct fuse_operations operations = {
  .getattr	= do_getattr,
  .readdir	= do_readdir,
  .read		= do_read,
  .mkdir    = do_mkdir,
  .mknod    = do_mknod,
  .write	= do_write,
  .utimens  = do_utimens,
  .destroy  = fuse_shutdown,
};

int main(int argc, char *argv[]) {
  return fuse_main(argc, argv, &operations, NULL);
}

