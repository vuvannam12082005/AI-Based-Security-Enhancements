#include "syscall_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>

#include "syscall_monitor.skel.h"

static volatile sig_atomic_t stop = 0;

static void handle_sig(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    struct syscall_event *e = (struct syscall_event *)data;
    // JSON line (stdout) for Python to parse
    // keep minimal + stable keys
    printf("{\"ts_ns\":%llu,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,"
           "\"comm\":\"%s\",\"filename\":\"%s\",\"syscall\":\"execve\"}\n",
           (unsigned long long)e->ts_ns, e->pid, e->ppid, e->uid, e->gid,
           e->comm, e->filename);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    struct syscall_monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    skel = syscall_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = syscall_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = syscall_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    while (!stop) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    syscall_monitor_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
