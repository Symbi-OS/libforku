#include <stdlib.h>
#include <stdio.h> 
#include <signal.h> 
#include <assert.h>
#include <unistd.h>
#include <stdint.h>

#define TEST_MALLOC_SIZE 1024 * 1024 * 1024ULL

volatile int g_signaled = 0;
unsigned int freeptr = 0;

void handle_sig(int sig)  {
    (void)sig; 
    g_signaled = 1;
}

char buf[1024 * 1024 * 1024 * 8ULL];

void* my_malloc(size_t n) {
    void *rtn = &buf[freeptr];
    freeptr += n;
    return rtn;
}

void print_tid_ptr() {
    uint64_t tidptr;
    asm volatile("mov %%fs:0x0, %0" : "=r"(tidptr));
    tidptr += 0x2d0;

    printf("TID_PTR: 0x%lx\n", tidptr);
}

int main() {
    print_tid_ptr();

    /* 
     * If you pre-allocate the array without touching pages immediately, but
     * touch the pages after a signal is received, the program appears to be
     * working in a stable way.
     */
    //char* m = (char*)malloc(TEST_MALLOC_SIZE);

    uint64_t var;
    asm ("movq %%fs:0x10, %0" : "=r" (var));
    printf("correct tid?? 0x%lx\n", var);

    uint64_t fsbase;
    asm("rdfsbase %0" : "=r" (fsbase));

    printf("fsbase: 0x%lx\n", fsbase);
    printf("diff: 0x%lx\n", var - fsbase);

    unsigned long flags = 0x01000000 | 0x200000 | SIGCHLD;
    printf("flags: 0x%lx\n", flags);

    signal(SIGUSR1, handle_sig);

    while (1) {
        asm volatile("nop");

        if (g_signaled) {
            g_signaled = 0;

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
            char* m = (char*)malloc(TEST_MALLOC_SIZE);
            for (size_t i = 0; i < TEST_MALLOC_SIZE - 1; ++i) {
                m[i] = 0xff;
            }
        }
    }

    return 0;
}
