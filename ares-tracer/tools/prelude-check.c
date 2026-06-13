// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>

#define PRELUDE_BYTES 16

static void dump_prelude(const char *label, void *func)
{
    unsigned char *p = (unsigned char *)func;
    printf("  %-32s @%p  ", label, func);
    for (int i = 0; i < PRELUDE_BYTES; i++)
        printf("%02x ", p[i]);
    printf("\n");
    fflush(stdout);
}

// __builtin_return_address(0) reads the saved LR from the stack frame.
// The prologue (stp x29, x30, [sp, #-N]!) runs before user code, saving
// whatever x30 held at function entry. If uretprobe has swapped x30 with a
// kernel trampoline address before the prologue ran, that trampoline address
// is what gets saved — and what __builtin_return_address(0) reads back.
__attribute__((noinline)) int target_uprobe(int x)
{
    void *lr = __builtin_return_address(0);
    printf("  [target_uprobe]    LR = %p\n", lr);
    fflush(stdout);
    return x + 1;
}

__attribute__((noinline)) int target_uretprobe(int x)
{
    void *lr = __builtin_return_address(0);
    printf("  [target_uretprobe] LR = %p\n", lr);
    fflush(stdout);
    return x * 2;
}

static void pause_prompt(const char *msg)
{
    printf("\n>>> %s\nPress ENTER to continue...", msg);
    fflush(stdout);
    getchar();
    printf("\n");
}

int main(void)
{
    int pid = getpid();

    printf("=== prelude-check ===\n");
    printf("PID: %d\n\n", pid);
    printf("Function addresses:\n");
    printf("  target_uprobe    @ %p\n", (void *)target_uprobe);
    printf("  target_uretprobe @ %p\n", (void *)target_uretprobe);
    printf("\nAttach commands (run in another terminal):\n");
    printf("  uprobe only:    ./ares-tracer -p %d -I prelude-check -i target_uprobe\n", pid);
    printf("  uretprobe only: ./ares-tracer -p %d -I prelude-check -r target_uretprobe\n", pid);
    printf("  both:           ./ares-tracer -p %d -I prelude-check -i \"target_\"\n\n", pid);

    printf("=== [1] BEFORE ATTACHMENT (baseline LR) ===\n");
    dump_prelude("target_uprobe", (void *)target_uprobe);
    dump_prelude("target_uretprobe", (void *)target_uretprobe);
    printf("  calling functions to capture baseline LR...\n");
    target_uprobe(0);
    target_uretprobe(0);

    pause_prompt("Attach ares-tracer to the PID above, then press ENTER.");

    printf("=== [2] AFTER ATTACHMENT (before call) ===\n");
    dump_prelude("target_uprobe", (void *)target_uprobe);
    dump_prelude("target_uretprobe", (void *)target_uretprobe);

    pause_prompt("About to call both functions.");

    int r1 = target_uprobe(10);
    int r2 = target_uretprobe(10);

    printf("=== [3] AFTER CALL ===\n");
    dump_prelude("target_uprobe", (void *)target_uprobe);
    dump_prelude("target_uretprobe", (void *)target_uretprobe);
    printf("\ntarget_uprobe(10)    = %d\n", r1);
    printf("target_uretprobe(10) = %d\n", r2);

    pause_prompt("Done.");
    return 0;
}
