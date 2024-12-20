/**
 * @file bpf_psd_prog.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:46:42
 *
 * @copyright Copyright (c) 2024
 *
 */

const char* BPF_PSD_PROGRAM = R"(
#include <linux/kernel.h>
#include <linux/ptrace.h>

struct psd_event_t {
    int pid;
    int type;
    char name[32];
    unsigned long ip;
    unsigned long time;
    unsigned long cred_p; // current->cred
    unsigned long cred_hash;
    unsigned long user_namespace_hash;
};


BPF_PERF_OUTPUT(psd_events);

int psd_dump_cred(struct pt_regs *ctx) {
    struct psd_event_t event = {};
    struct task_struct *cu = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.name, sizeof(event.name));
    event.ip = ctx->ip;
    event.time = bpf_ktime_get_ns();
    event.type = 2;

    int rc = kstack_key.perf_submit(ctx, &event, sizeof(struct psd_event_t));
    if (rc < 0)
        bpf_trace_printk("perf_output failed: %d\\n", rc);

    return 0;
}

)";
