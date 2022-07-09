/*
* Copyright (c) International Business Machines Corp., 2007
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
* the GNU General Public License for more details.
*/



#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <sys/syscall.h>
#include <signal.h>
#include "test.h"

#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */

static char child_stack[STACK_SIZE];

static int dummy_child(void *v)
{
	(void) v;
	return 0;
}

int quick_clone_pid(int (*fn)(void *))
{

return clone(fn, child_stack + STACK_SIZE, CLONE_NEWPID, NULL);
}


static int check_newpid(void)
{
	int pid, status;


	pid = clone(dummy_child, child_stack + STACK_SIZE, CLONE_NEWPID, NULL);
	if (pid == -1)
		tst_brk(TCONF | TERRNO, "CLONE_NEWPID not supported");
	wait(&status);

	return 0;
}
