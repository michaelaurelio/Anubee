#include <assert.h>
#include <string.h>
#include <linux/types.h>
#include "syscalls/syscalls.h"
#include "syscalls/unwind_regs.h"

int main(void)
{
    struct syscalls_stack_snapshot s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < 31; i++)
        s.regs[i] = 0x1000ULL + i;       /* x0..x30 */
    s.sp = 0xdead0000ULL;
    s.pc = 0xbeef0000ULL;

    struct ares_unwind_regs r;
    unwind_regs_from_snapshot(&s, &r);

    for (int i = 0; i < 31; i++)
        assert(r.x[i] == 0x1000ULL + i);
    assert(r.sp == 0xdead0000ULL);
    assert(r.pc == 0xbeef0000ULL);
    /* x29/x30 must agree with the legacy fp/lr mirror */
    assert(r.x[29] == s.regs[29]);
    assert(r.x[30] == s.regs[30]);
    return 0;
}
