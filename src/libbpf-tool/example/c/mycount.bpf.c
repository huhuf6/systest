// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on syscount(8) from BCC by Sasha Goldshtein
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscount.h"
#include "maps.bpf.h"

const volatile pid_t filter_pid = 0;
__u64 targetnamespace=0;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct data_t);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} data SEC(".maps");

static __always_inline
void save_proc_name(struct data_t *val)
{
	struct task_struct *current = (void *)bpf_get_current_task();

	/* We should save the process name every time because it can be
	 * changed (e.g., by exec).  This can be optimized later by managing
	 * this field with the help of tp/sched/sched_process_exec and
	 * raw_tp/task_rename. */
	BPF_CORE_READ_STR_INTO(&val->comm, current, group_leader, comm);
}

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

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
	u64 id = bpf_get_current_pid_tgid();
	static const struct data_t zero;
	pid_t pid = id >> 32;
	struct data_t *val;
	u64 *start_ts;
	u32 tid = id;
	u32 key;
	if(!getcurpidnamespace(targetnamespace))	
		return 0;
	/* this happens when there is an interrupt */
	if (args->id == -1)
		return 0;

	if (filter_pid && pid != filter_pid)
		return 0;
	

	key = args->id;
	val = bpf_map_lookup_or_try_init(&data, &key, &zero);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
			save_proc_name(val);		
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
