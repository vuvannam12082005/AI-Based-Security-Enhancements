// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "syscall_monitor.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16
#define PATH_LEN 256


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline __u32 get_ppid_tgid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);

    e->ppid = get_ppid_tgid();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // execve(filename, argv, envp) => args[0] is filename pointer
    const char *filename = (const char *)ctx->args[0];
    bpf_core_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
