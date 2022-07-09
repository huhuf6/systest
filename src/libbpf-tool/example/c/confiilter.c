// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "trace_helpers.h"
#include "btf_helpers.h"
#include "confiilter.skel.h"
#include "confiilter.h"
#include "ebpftime.h"

#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS	100

#define NSEC_PER_SEC		1000000000ULL

static volatile sig_atomic_t exiting = 0;

FILE *logfp=NULL;
bool outlog=false;
char filename[30];

struct print_packet {
	char src[16];
	char dst[16];
	char l3proto[10];
	char l4proto[10];
	unsigned short sport;
	unsigned short dport;
	unsigned packetsize;
};

uint ifindex=0;



static void sig_int(int signo)
{
	exiting = 1;
}


static uint getpidnamespaceinum()
{
 system("ps -h -o pidns -p $$ >test");
 FILE *fp=fopen("./test","r");
 char strbuf[20]="";
 int n=0;
 while((strbuf[n++]=fgetc(fp))!=EOF);
 long int namespaceinum=0;
 namespaceinum=strtol(strbuf,NULL,0);
 printf("cur ns:%ld\n",namespaceinum);
 fclose(fp);
 return namespaceinum;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct packet *e = data;
	struct print_packet printinfo;
	strcpy(printinfo.l3proto, "IP");
	inet_ntop(AF_INET, &e->src, printinfo.src, 16);
	inet_ntop(AF_INET, &e->dst, printinfo.dst, 16);
	printinfo.sport = ntohs(e->sport);
	printinfo.dport = ntohs(e->dport);
	printinfo.packetsize = e->packetsize;
	if(e->l4proto==IPPROTO_TCP)
	strcpy(printinfo.l4proto, "TCP");
	if(e->l4proto==IPPROTO_UDP)
	strcpy(printinfo.l4proto, "UDP");
	if(outlog)
	{
		FILE *fp=fopen(filename,"a");
		fprintf(fp,"%s %s %s:%-5d  %s:%d  %3sv4 %3s %d\n", get_cur_time(),"[INFO]",printinfo.src, printinfo.sport, printinfo.dst, printinfo.dport, printinfo.l3proto, printinfo.l4proto,printinfo.packetsize);
		fclose(fp);
	}
	else
	printf("%s %s %s:%-5d  %s:%d  %3sv4 %3s %d\n", get_cur_time(),"[INFO]",printinfo.src, printinfo.sport, printinfo.dst, printinfo.dport, printinfo.l3proto, printinfo.l4proto,printinfo.packetsize);
	
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}


static const struct argp_option opts[] = {
	
	{ "net interface", 'i', "IF", 0, "interface to trace"},
	{ 0, 'l', 0, 0, "save log"},
	{0}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	time_t tmp;   
    	struct tm *timp; 
	switch (key) {
	case 'l':
    		time(&tmp);   
    		timp = localtime(&tmp);
    		sprintf(filename,"%d-%d-%d %d:%d:%d", (1900 + timp->tm_year), ( 1 + timp->tm_mon), timp->tm_mday,
                                (timp->tm_hour), timp->tm_min, timp->tm_sec); 
               strcat(filename,".log.confilter");
		outlog=true;
		break;
	case 'i':
		errno = 0;
		ifindex = if_nametoindex(arg);
		printf("IF: %s  Index: %d\n", arg,ifindex);
		if (ifindex <= 0) {
			fprintf(stderr, "Invalid if: %s\n", arg);
			argp_usage(state);
		}
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





int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
	};
	struct confiilter_bpf *skel;
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = confiilter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	/*init global variable */
	skel->bss->ifindex=ifindex;
	/* ensure BPF program only handles write() syscalls from our process */
	uint curns=getpidnamespaceinum();
	
	
	/* Load & verify BPF programs */
	err = confiilter_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = confiilter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}
	
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	if(outlog)
	{
		logfp=fopen(filename,"a");
		fprintf(logfp,"%44s %20s %18s %3s %3s  \n", "SRC ","DST ", "IPver", "Type","Bytes");
		fclose(logfp);
	}
	else
	printf("%44s %20s %18s %3s %3s  \n", "SRC ","DST ", "IPver", "Type","Bytes");
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
	
	confiilter_bpf__destroy(skel);
	return -err;
}
