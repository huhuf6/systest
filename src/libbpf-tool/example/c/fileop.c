// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 ap
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fileop.h"
#include "fileop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "ebpftime.h"


/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS	100

#define NSEC_PER_SEC		1000000000ULL

static volatile sig_atomic_t exiting = 0;

FILE *logfp=NULL;
bool outlog=false;
char filename[30];

static struct env {
	pid_t pid;
	bool open;
	bool write;
	bool read;
	long int  curpidnamespace;
} env = {
	.pid = 0,
	.open = false,
	.write = false,
	.read = false,
	.curpidnamespace =0
	
};



static const struct argp_option opts[] = {
	
	{ "pid", 'p', "PID", 0, "Process ID to trace"},
	{ "open", 'o', NULL, 0, "Trace open"},
	{ "write", 'w', NULL, 0, "Trace write"},
	{ "read", 'r', NULL, 0, "Trace read"},
	{ "cpidnamespace",'c', "INUM",0,"pid namespace"},
	{"save out put log",'l',NULL,0,"log"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	long int pid;
	long int curns;
	time_t tmp;   
    	struct tm *timp;
	switch (key) {
	case 'l':
    		time(&tmp);   
    		timp = localtime(&tmp);
    		sprintf(filename,"%d-%d-%d %d:%d:%d", (1900 + timp->tm_year), ( 1 + timp->tm_mon), timp->tm_mday,
                                (timp->tm_hour), timp->tm_min, timp->tm_sec); 
               strcat(filename,".log.fileop");
		outlog=true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 'c':
		errno = 0;
		curns = strtol(arg, NULL, 10);
		fprintf(stderr, "%ld ns: \n", curns);
		if (errno || curns < 0) {
			fprintf(stderr, "Invalid ns: %s\n", arg);
			argp_usage(state);
		}
		env.curpidnamespace = curns;
		break;
	case 'o':
		env.open = true;
		break;
	case 'w':
		env.write = true;
		break;
	case 'r':
		env.read = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	

	int fd, err;


	/* prepare fields */
	
	if (e->ret >= 0) {
		fd = e->ret;
		err = 0;
	} else {
		fd = -1;
		err = - e->ret;
	}

	/* print output */
	if(outlog)
	{
		logfp=fopen(filename,"a");
		fprintf(logfp,"%s %s %-6d %-16s %3d %4d %-10s %-20d", get_cur_time(),"[INFO]",e->pid, e->comm, fd, err,e->eventtype,e->readbuf);
		fprintf(logfp,"%s\n", e->fname);
		fclose(logfp);
	}
	else
	{
	printf("%s %s %-6d %-16s %3d %4d %-10s %-20d", get_cur_time(),"[INFO]",e->pid, e->comm, fd, err,e->eventtype,e->readbuf);
	
	printf("%s\n", e->fname);
	}
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
	};
	struct perf_buffer *pb = NULL;
	struct fileop_bpf *obj;
	
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	

	obj = fileop_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->tpid = env.pid;
	obj->rodata->sopen = env.open;
	obj->rodata->swrite = env.write;
	obj->rodata->sread = env.read;
	obj->rodata->selfpid = getpid();
	obj->bss->targetnamespace=env.curpidnamespace;

	err = fileop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = fileop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	/* print headers */
	
	if(outlog)
	{
		logfp=fopen(filename,"a");
		fprintf(logfp,"%36s %8s %14s %4s %-10s %-20s", "PID", "COMM", "FD", "ERR","EVENT","READBUF");
		fprintf(logfp,"%s\n", "PATH");
		fclose(logfp);
	}
	else
	{
	printf("%36s %8s %14s %4s %-10s %-20s", "PID", "COMM", "FD", "ERR","EVENT","READBUF");
	printf("%s\n", "PATH");
	}
	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	fileop_bpf__destroy(obj);
	

	return err != 0;
}
