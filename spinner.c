#include <stdlib.h>
#include <stdio.h> 
#include <signal.h> 
#include <assert.h>

//#define MEM_ALLOC_TEST_BEFORE
#define MEM_ALLOC_TEST_AFTER

extern char __libc_single_threaded;

volatile int g_signaled = 0;

void handle_sig(int sig)  {
    (void)sig; 
    g_signaled = 1;
} 

int main() {
#ifdef MEM_ALLOC_TEST_BEFORE
    char* m = (char*)malloc(1024ULL * 1024ULL * 1024ULL); // 1 MB
#endif

    signal(SIGUSR1, handle_sig); 

    size_t i = 0;
    while (1) {
        ++i;
        asm volatile ("nop");

        if (i > 10000000000ULL) {
            //printf("tick!\n");
            i = 0;
        }

        if (g_signaled == 1) {
            //printf("Signaled!\n");
            g_signaled = 0;

#ifdef MEM_ALLOC_TEST_AFTER
            char* m = (char*)malloc(1024ULL * 1024ULL * 1024ULL); // 1 MB
#endif

            for (size_t i = 0; i < 1024 * 1024; i += 4096) {
                m[i] = (char)i;
            }
        }
    }

    return 0;
}