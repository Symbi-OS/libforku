#include <stdlib.h>
#include <stdio.h> 
#include <signal.h> 
#include <assert.h>
#include <unistd.h>
#include <stdint.h>

// 500 MB
#define TEST_MALLOC_SIZE 1024 * 1024 * 500ULL

volatile int g_signaled = 0;

void handle_sig(int sig)  {
    (void)sig; 
    g_signaled = 1;
}

int main() {
  /* 
   * If you pre-allocate the array without touching pages immediately, but
   * touch the pages after a signal is received, the program appears to be
   * working in a stable way.
   */
  //char* m = (char*)malloc(TEST_MALLOC_SIZE);

  signal(SIGUSR1, handle_sig);

  while (1) {
    asm volatile("nop");

    if (g_signaled) {
      g_signaled = 0;
      exit(0);
      
      /*  WORKS  */
      // buf[sizeof(buf) - 1] = 0xff;

      /*  WORKS  */
      // for (size_t i = 0; i < sizeof(buf) - 1; ++i) {
      //     buf[i] = 0xff;
      // }

      /*  WORKS  */
      // char* m = (char*)my_malloc(TEST_MALLOC_SIZE);
      // for (size_t i = 0; i < TEST_MALLOC_SIZE - 1; ++i) {
      //     m[i] = 0xff;
      // }

      /*  WORKS (only if signal is sent before forku call) */
      //write(1, "Test\n", 5);

      /*  DOESN'T WORK  */
      /*  Suspicion: %fs relative addressing is the problem   */

      /*char* m = (char*)malloc(TEST_MALLOC_SIZE);
      for (size_t i = 0; i < TEST_MALLOC_SIZE - 1; ++i) {
        m[i] = 0xff;
      }

      printf("Allocated %lld MB\n", TEST_MALLOC_SIZE / 1024 / 1024);*/
    }
  }

  return 0;
}
