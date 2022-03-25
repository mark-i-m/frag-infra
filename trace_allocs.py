#!/usr/bin/env python2
#
# Based on stacksnoop

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct
import time
import sys

# arguments
DURATION=None
if len(sys.argv) == 2:
    DURATION = int(sys.argv[1])

debug = 0

ALLOC_PAGES = (1 << 0)
FREE_PAGES  = (1 << 1)
MMAP        = (1 << 2)
MUNMAP      = (1 << 3)
BRK         = (1 << 4)
ANON        = (1 << 5)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mman.h>

#define ALLOC_PAGES (1 << 0)
#define FREE_PAGES  (1 << 1)
#define MMAP        (1 << 2)
#define MUNMAP      (1 << 3)
#define BRK         (1 << 4)
#define ANON        (1 << 5)

struct data_t {
    u64 stack_id;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 order;
    u8 flags;
};

BPF_STACK_TRACE(stack_traces, 1024);
BPF_PERF_OUTPUT(events);
BPF_ARRAY(norder0, u64, 1);

static void do_trace(struct pt_regs *ctx, u8 flags, u64 order) {
    u64 *val;
    struct data_t data = {};
    int zero = 0;

    data.stack_id = stack_traces.get_stackid(ctx, 0),
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.order = order;
    data.flags = flags;

    if (order == 0) {
        val = norder0.lookup(&zero);
        if(val) lock_xadd(val, 1);
    } else {
        events.perf_submit(ctx, &data, sizeof(data));
    }
}

void kprobe____alloc_pages_nodemask(struct pt_regs *ctx, gfp_t gfp, unsigned int order) {
    do_trace(ctx, ALLOC_PAGES, order);
}

void kprobe____free_pages(struct pt_regs *ctx, struct page *page, unsigned int order) {
    do_trace(ctx, FREE_PAGES, order);
}

void kprobe__sys_mmap_pgoff(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    do_trace(ctx, MMAP | (flags & MAP_ANONYMOUS ? ANON : 0), length >> 12);
}

void kprobe__do_munmap(struct pt_regs *ctx, void *addr, size_t length) {
    do_trace(ctx, MUNMAP, length >> 12);
}

void kprobe__sys_brk(struct pt_regs *ctx) {
    // Hard to tell the length from the system call, unfortunately...
    do_trace(ctx, BRK | ANON, 1);
}
"""

if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
#for sc in ["mmap", "munmap", "brk"]:
#    fnname = b.get_syscall_fnname(sc)
#    b.attach_kprobe(event=fnname, fn_name="syscall__%s" % sc)

TASK_COMM_LEN = 16  # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
        ("stack_id", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("order", ct.c_ulonglong),
        ("flags", ct.c_uint8),
    ]

matched = b.num_open_kprobes()
if matched < 2:
    print("Function not found. Exiting.")
    exit()

stack_traces = b.get_table("stack_traces")
START = time.time()
buffered_events = []

# header
print("%-18s %-12s %-6s %-3s %s" %
        ("TIME(s)", "COMM", "PID", "CPU", "FUNCTION"))

def repr_flags(flags):
    s = ""

    if flags & ALLOC_PAGES != 0:
        s += "alloc_pages"
    if flags & FREE_PAGES != 0:
        s += "free_pages"
    if flags & MMAP != 0:
        s += "mmap"
    if flags & MUNMAP != 0:
        s += "munmap"
    if flags & BRK != 0:
        s += "brk"

    if flags & ANON != 0:
        s += " anon"

    return s

def print_event(cpu, data, size):
    global buffered_events

    event = ct.cast(data, ct.POINTER(Data)).contents

    buffered_events.append((event.comm.decode(), event.pid, cpu,
        repr_flags(event.flags), event.order))

    if len(buffered_events) % 100000 == 0:
        for comm, pid, cpu, flags, order in buffered_events:
            print("%-12.12s %-6d %-3d %s %lu" % (comm, pid, cpu, flags, order))
        buffered_events = []

    # uncomment to print stack traces
    #for addr in stack_traces.walk(event.stack_id):
    #    sym = b.ksym(addr, show_offset=True)
    #    print("\t%s" % sym)

def end():
    global buffered_events

    # print any unprinted buffered events
    for comm, pid, cpu, flags, order in buffered_events:
        print("%-12.12s %-6d %-3d %s %lu" % (comm, pid, cpu, flags, order))

    # counter of 0-order events
    print("0-order events: %d" % b["norder0"][ct.c_int(0)].value)

    # exit
    print("Exiting after %d seconds." % (time.time() - START), file=sys.stderr)
    exit()

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.kprobe_poll()
        time.sleep(0.1)
    except KeyboardInterrupt:
        end()

    if DURATION is not None and time.time() - START >= DURATION * 60.:
        end()
