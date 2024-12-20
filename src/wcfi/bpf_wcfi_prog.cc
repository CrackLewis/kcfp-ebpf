/**
 * @file bpf_wcfi_prog.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:45:41
 *
 * @copyright Copyright (c) 2024
 *
 */

const char* BPF_WCFI_PROGRAM = R"(
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

#define WCFI_CALLSITE_FLAG 0x1
#define WCFI_EXCASM_FLAG 0x2

struct wcfi_event_t {
    int pid;
    int type;
    char name[32];
    unsigned long ip;
    unsigned long time;
    int kernel_stack;
    unsigned long reg_sp;
    unsigned long current_sp;
};

BPF_HASH(wcfi_callsite_bitmap, unsigned, uint8_t, 0x4000000);
BPF_HASH(wcfi_callsite_bitmap_maxmin, unsigned, unsigned, 2);
BPF_HASH(wcfi_init_stack, int, unsigned long, 1);
BPF_PERF_OUTPUT(wcfi_events);
BPF_STACK_TRACE(kstack_table, 0x1000);

int wcfi_dump_kstack(struct pt_regs *ctx) {
    struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
    unsigned long addrs[0x30];
    unsigned long stack_mask = ~((unsigned long)(1 << 16) - 1);

    bpf_get_stack(ctx, addrs, 0x30*8, 0);

    if (((unsigned long)ctx->sp & stack_mask)
        != ((unsigned long)cu->stack & stack_mask)) {
        int init_stack_idx = 0;
        unsigned long *init_stack = wcfi_init_stack.lookup(&init_stack_idx);
        // PID:0 (swapper/0)
        if (init_stack && cu->stack != *init_stack && cu->pid != 0) {
            struct wcfi_event_t event = {};
            struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
            event.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&event.name, sizeof(event.name));
            event.kernel_stack = kstack_table.get_stackid(ctx, BPF_F_REUSE_STACKID);
            event.reg_sp = ctx->sp;
            event.current_sp = (unsigned long)cu->stack;
            event.time = bpf_ktime_get_ns();
            event.ip = cu->thread.sp;
            event.type = 1;
            wcfi_events.perf_submit(ctx, &event, sizeof(struct wcfi_event_t));
            return 0;
        } // failed 
    }

    for(int i = 1; i < 0x30; i++) {
        unsigned idx = addrs[i] & 0xffffffff;
        uint8_t *val;

        val = wcfi_callsite_bitmap.lookup(&idx);
        if (idx == 0)
            break;
        // right callsite
        if (val) {
            if (*val == WCFI_CALLSITE_FLAG)
                continue;
            // exc asm may jump to/from somewhere without callsite
            if (*val == WCFI_EXCASM_FLAG) {
                i++;
                continue;
            }
        }
        if(!val) {
            unsigned max_idx = 0xffff, min_idx = 0x0;
            unsigned *max = wcfi_callsite_bitmap_maxmin.lookup(&max_idx);
            unsigned *min = wcfi_callsite_bitmap_maxmin.lookup(&min_idx);
            if (min && max && (idx > *max || idx < *min))
                continue;
        }if (idx != 0 && !val) {
            struct wcfi_event_t event = {};
            struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
            event.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&event.name, sizeof(event.name));
            event.kernel_stack = kstack_table.get_stackid(ctx, BPF_F_REUSE_STACKID);
            event.reg_sp = ctx->sp;
            event.current_sp = (unsigned long)cu->stack;
            event.time = bpf_ktime_get_ns();
            event.ip = addrs[i];
            wcfi_events.perf_submit(ctx, &event, sizeof(struct wcfi_event_t));
            break;
        }
    }

    return 0;
}

)";