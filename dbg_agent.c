// gcc -g -export-dynamic dbg_agent.c
#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <ucontext.h>
#include <dlfcn.h>

unsigned char orig_instruction;
unsigned char *breakpoint_address;
void *mprotect_address;

static void print_registers(ucontext_t *ucontext)
{
    printf("RAX: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RAX]);
    printf("RBX: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RBX]);
    printf("RCX: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RCX]);
    printf("RDX: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RDX]);
    printf("RSI: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RSI]);
    printf("RDI: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RDI]);
    printf("RBP: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RBP]);
    printf("RSP: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RSP]);
    printf("R8 : 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R8]);
    printf("R9 : 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R9]);
    printf("R10: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R10]);
    printf("R11: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R11]);
    printf("R12: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R12]);
    printf("R13: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R13]);
    printf("R14: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R14]);
    printf("R15: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_R15]);
    printf("RIP: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_RIP]);
    printf("EFL: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_EFL]);
    printf("CSGSFS: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_CSGSFS]);
    printf("ERR: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_ERR]);
    printf("TRAPNO: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_TRAPNO]);
    printf("OLDMASK: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_OLDMASK]);
    printf("CR2: 0x%llx\n", ucontext->uc_mcontext.gregs[REG_CR2]);
}

static void
backtrace(ucontext_t *context)
{
    unsigned frame_number = 0;

    void *ip = NULL;
    void **bp = NULL;

#if defined(REG_RIP)
    ip = (void *)context->uc_mcontext.gregs[REG_RIP];
    bp = (void **)context->uc_mcontext.gregs[REG_RBP];
#elif defined(REG_EIP)
    ip = (void *)context->uc_mcontext.gregs[REG_EIP];
    bp = (void **)context->uc_mcontext.gregs[REG_EBP];
#endif

    while (bp >= 8 && ip)
    {
        Dl_info dlinfo;
        if (!dladdr(ip, &dlinfo))
            break;

        const char *symbol = dlinfo.dli_sname;

        fprintf(stderr, "% 2d: %p <%s+%lu> (%s)\n",
                ++frame_number,
                ip,
                symbol ? symbol : "(?)",
                ip - dlinfo.dli_saddr,
                dlinfo.dli_fname);

        if (dlinfo.dli_sname && strcmp(dlinfo.dli_sname, "main") == 0)
            break;

        ip = bp[1];
        bp = (void **)bp[0];
    }
}

void handle_signal(int signum, siginfo_t *info, void *context)
{
    printf("Received signal: %d\n", signum);
    ucontext_t *ucontext = (ucontext_t *)context;
    print_registers(ucontext);
    backtrace(context);
    // ucontext->uc_mcontext.gregs[REG_EFL] |= 0x100; // Set trap flag to single step

    if (mprotect(mprotect_address, 1, PROT_READ | PROT_EXEC | PROT_WRITE) == -1)
    {
        perror("mprotect");
        return;
    }
    *breakpoint_address = orig_instruction;
    if (mprotect(mprotect_address, 1, PROT_READ | PROT_EXEC) == -1)
    {
        perror("mprotect");
        return;
    }
    printf("Restored original instruction\n");
}

void handle_segv(int signum, siginfo_t *info, void *context)
{
    printf("handle_segv: Received signal: %d\n", signum);
    ucontext_t *ucontext = (ucontext_t *)context;
    print_registers(ucontext);
    backtrace(context);
    printf("handle_segv: End");
}

void my_fun()
{
    printf("1\n");
    printf("2\n");
    printf("3\n");
}

int main()
{
    printf("Start\n");

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sa.sa_sigaction = handle_signal;

    if (sigaction(SIGILL, &sa, NULL) == SIG_ERR)
    {
        printf("\nCan't catch SIGILL\n");
    }
    if (sigaction(SIGTRAP, &sa, NULL) == SIG_ERR)
    {
        printf("\nCan't catch SIGTRAP\n");
    }

    struct sigaction sa2;
    sa2.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sa2.sa_sigaction = handle_segv;
    if (sigaction(SIGSEGV, &sa2, NULL) == SIG_ERR)
    {
        printf("\nCan't catch SIGSEGV\n");
    }

    // breakpoint_address = (void *)0x5555555557f5;
    // breakpoint_address = (void *)0x555555555789;
    breakpoint_address = my_fun + 23;
    printf("Breakpint address: %lx\n", (unsigned long)breakpoint_address);
    orig_instruction = *breakpoint_address;

    long page_size = sysconf(_SC_PAGE_SIZE);
    printf("Page size: %ld\n", page_size);
    mprotect_address = (void *)((unsigned long)breakpoint_address & 0xfffffffffffff000);
    printf("mprotect_address: %lx\n", (unsigned long)mprotect_address);

    printf("Setting write protection\n");
    if (mprotect(mprotect_address, 1, PROT_READ | PROT_EXEC | PROT_WRITE) == -1)
    {
        perror("mprotect");
        return -1;
    }
    printf("Setting breakpoint instruction\n");
    *breakpoint_address = 0xce;
    printf("Setting execute protection\n");
    if (mprotect(mprotect_address, 1, PROT_READ | PROT_EXEC) == -1)
    {
        perror("mprotect");
        return -2;
    }

    printf("Calling my_fun()\n");
    my_fun();
    printf("End\n");
    return 0;
}
