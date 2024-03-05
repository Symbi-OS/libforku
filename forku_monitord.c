#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

char dir_list[ 256 ][ 256 ];
int curr_dir_idx = -1;

char files_list[ 256 ][ 256 ];
int curr_file_idx = -1;

char files_content[ 256 ][ 256 ];
int curr_file_content_idx = -1;

int sample_pids[5] = { 4554, 7242, 6592, 10325, 32554 };

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
  if (strcmp(path, "/") == 0) {
    st->st_mode = S_IFDIR | 0555;
    st->st_nlink = 2; // Standard for directories
  } else {
    // Check if the path corresponds to one of the PID-based directories
    int pid = atoi(path + 1); // Convert the path to an integer, skipping the leading '/'
    if (pid > 0) {
      st->st_mode = S_IFDIR | 0555;
      st->st_nlink = 2; // Standard for directories
    } else {
      return -ENOENT;
    }
  }
  return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  (void)offset; // Unused parameter
  (void)fi; // Unused parameter

  if (strcmp(path, "/") == 0) {
    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);

    char dir_name[64] = { 0 };
    size_t entries = sizeof(sample_pids) / sizeof(sample_pids[0]);
    for(size_t i = 0; i < entries; ++i) {
      sprintf(dir_name, "%d", sample_pids[i]);
      filler(buffer, dir_name, NULL, 0);
    }
  } else {
    // Handle other directories if your filesystem supports them
    return -ENOENT;
  }

  return 0; // Successy
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path; // Mark unused parameter
  (void)buffer; // Mark unused parameter
  (void)size; // Mark unused parameter
  (void)offset; // Mark unused parameter
  (void)fi; // Mark unused parameter
  printf("read called\n");
  return 0; // Return success, indicating no data read
}

static int do_mkdir(const char *path, mode_t mode) {
  (void)path; // Mark unused parameter
  (void)mode; // Mark unused parameter
  printf("mkdir called\n");
  return 0; // Return success
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev) {
  (void)path; // Mark unused parameter
  (void)mode; // Mark unused parameter
  (void)rdev; // Mark unused parameter
  printf("mknod called\n");
  return 0; // Return success
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info) {
  (void)path; // Mark unused parameter
  (void)buffer; // Mark unused parameter
  (void)size; // Mark unused parameter
  (void)offset; // Mark unused parameter
  (void)info; // Mark unused parameter
  printf("write called\n");
  return size; // Pretend that the write was successful and all bytes were written
}

static struct fuse_operations operations = {
  .getattr	= do_getattr,
  .readdir	= do_readdir,
  .read		= do_read,
  .mkdir		= do_mkdir,
  .mknod		= do_mknod,
  .write		= do_write,
};

int main( int argc, char *argv[] ) {
  return fuse_main(argc, argv, &operations, NULL);
}

