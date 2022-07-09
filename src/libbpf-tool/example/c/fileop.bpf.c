// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "fileop.h"

const volatile bool sopen = 0;
const volatile bool swrite = 0;
const volatile bool sread = 0;
const volatile pid_t tpid=0;
const volatile bool targ_failed = false;
const volatile pid_t selfpid = 0;

__u64 targetnamespace=0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");


static __always_inline
bool getcurpidnamespace(u64 target)
{
       struct task_struct *task;
       task = (struct task_struct *)bpf_get_current_task();
       //ts->nsproxy->pid_ns_for_children->ns.inum
       u64 curpidns = (u64)BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
 	 //curpidns = 1;
	//int pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("curprcocess ns %ld.\n", curpidns); 
	bpf_printk("target ns %ld.\n", target); 
	if (curpidns == target||target==0)
		return true;

	//bpf_printk("BPF triggered from the PID %d.\n", pid);
         
	return false;
}

static __always_inline
bool trace_allowed(u32 pid)
{
	u32 cpid;

	/* filters */
	if(pid==0)
	return true;
	
	if (pid) {
		cpid = (u32)bpf_get_current_pid_tgid();
		if (pid != cpid) {
			return false;
		}
	}
	return true;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tpid)&&sopen) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[0];
		args.flags = (int)ctx->args[1];
		args.type =1;
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tpid)&&sopen) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[1];
		args.flags = (int)ctx->args[2];
		args.type =1;
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tpid)&&sread) {
		struct args_t args = {};
		args.readbuf = ctx->args[2];
		args.type =3;
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tpid)&&swrite) {
		struct args_t args = {};
		args.type =2;
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event *event;
	int zero = 0;
	struct args_t *ap;
	event = bpf_map_lookup_elem(&heap, &zero);
	//if event is NULL
	if(!event)
		return 0;
	//namespace filter
	if(!getcurpidnamespace(targetnamespace))	
		return 0;
	int ret;
	u32 pid = bpf_get_current_pid_tgid();
        if(pid==selfpid)
        return 0;
        if(tpid&&tpid!=pid)
        return 0;
	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup;	/* want failed only */

	/* event data */
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);
	event->flags = ap->flags;
	event->ret = ret;
	if(ap->type==1)
	strcpy(event->eventtype, "OPEN");
	if(ap->type==2)
	strcpy(event->eventtype, "WRITE");
	if(ap->type==3)
	{
	strcpy(event->eventtype, "READ");
	//strcpy(event->readbuf, ap->readbuf);
	event->readbuf=ap->readbuf;
	}
	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}
char LICENSE[] SEC("license") = "GPL";
