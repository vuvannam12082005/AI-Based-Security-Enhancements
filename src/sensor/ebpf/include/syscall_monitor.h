#pragma once

/* 
 * BPF side: vmlinux.h defines __u64/__u32/... and usually sets __VMLINUX_H__
 * User side: linux/types.h defines __u64/__u32/...
 * => Do NOT redefine these types here.
 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define MAX_PATH_LEN 256

struct syscall_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __s32 syscall_ret;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_PATH_LEN];
};
