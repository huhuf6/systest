/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILEOP_H
#define __FILEOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)
#define MAX_READ 512

struct args_t {
	const char *fname;
	int flags;
	int type;//open 1 write 2 read 3
	int  readbuf;
};

struct event {
	/* user terminology for pid: */
	__u64 ts;
	pid_t pid;
	uid_t uid;
	int ret;
	int flags;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
	char eventtype[TASK_COMM_LEN];
	int  readbuf;
};

#endif /* __OPENSNOOP_H */
