#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#define TST_NO_DEFAULT_MAIN
#include "test.h"
struct tst_test *tst_test;

static const char *tid;
static int iterations = 1;
static float duration = -1;
static float timeout_mul = -1;
static pid_t main_pid, lib_pid;
static int mntpoint_mounted;
static int ovl_mounted;
static struct timespec tst_start_time; /* valid only for test pid */


struct results {
	int passed;
	int skipped;
	int failed;
	int warnings;
	int broken;
	unsigned int timeout;
};




static struct results *results;

static int ipc_fd;

extern void *tst_futexes;
extern unsigned int tst_max_futexes;

static char ipc_path[1064];
const char *tst_ipc_path = ipc_path;

static char shm_path[1024];

int TST_ERR;
int TST_PASS;
long TST_RET;

static void do_cleanup(void);
static void do_exit(int ret) __attribute__ ((noreturn));

//确认测试函数存在
static void assert_test_fn(void)
{
	int cnt = 0;

	if (tst_test->test)
		cnt++;

	if (tst_test->test_all)
		cnt++;

	if (tst_test->sample)
		cnt++;
	printf("cnt:%d\n",cnt);
	if (!cnt)
		tst_brk(TBROK, "No test function specified");

	if (cnt != 1)
		tst_brk(TBROK, "You can define only one test function");

	if (tst_test->test && !tst_test->tcnt)
		tst_brk(TBROK, "Number of tests (tcnt) must be > 0");

	if (!tst_test->test && tst_test->tcnt)
		tst_brk(TBROK, "You can define tcnt only for test()");
}
//static void parse_opts(int argc, char *argv[])


//在shm中存储暂存results结果
static void setup_ipc(void)
{
	size_t size = getpagesize();

	if (access("/dev/shm", F_OK) == 0) {
		snprintf(shm_path, sizeof(shm_path), "/dev/shm/ltp_%s_%d",
		         tid, getpid());
	} 
	/*else {
		char *tmpdir;

		if (!tst_tmpdir_created())
			tst_tmpdir();

		tmpdir = tst_get_tmpdir();
		snprintf(shm_path, sizeof(shm_path), "%s/ltp_%s_%d",
		         tmpdir, tid, getpid());
		free(tmpdir);
	}*/

	ipc_fd = open(shm_path, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (ipc_fd < 0)
		tst_brk(TBROK | TERRNO, "open(%s)", shm_path);
	chmod(shm_path, 0666);

	ftruncate(ipc_fd, size);

	results = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, ipc_fd, 0);

	close(ipc_fd);
}


static void cleanup_ipc(void)
{
	size_t size = getpagesize();

	if (ipc_fd > 0 && close(ipc_fd))
		tst_res(TWARN | TERRNO, "close(ipc_fd) failed");

	if (shm_path[0] && !access(shm_path, F_OK) && unlink(shm_path))
		tst_res(TWARN | TERRNO, "unlink(%s) failed", shm_path);

	if (results) {
		msync((void*)results, size, MS_SYNC);
		munmap((void*)results, size);
		results = NULL;
	}
}

//测试执行前准备
static void do_setup(int argc, char *argv[])
{
	
	if (!tst_test)
		tst_brk(TBROK, "No tests to run");

	printf("do setup\n");
	assert_test_fn();
        if (tst_test->needs_root && geteuid() != 0)
		tst_brk(TCONF, "Test needs to be run as root");
	setup_ipc();
}


//打印结果
static void print_result(const char *file, const int lineno, int ttype,
                         const char *fmt, va_list va)
{
	char buf[1024];
	char *str = buf;
	int ret, size = sizeof(buf), ssize, int_errno, buflen;
	const char *str_errno = NULL;
	const char *res;

	switch (TTYPE_RESULT(ttype)) {
	case TPASS:
		res = "TPASS";
	break;
	case TFAIL:
		res = "TFAIL";
	break;
	case TBROK:
		res = "TBROK";
	break;
	case TCONF:
		res = "TCONF";
	break;
	case TWARN:
		res = "TWARN";
	break;
	case TINFO:
		res = "TINFO";
	break;
	default:
		tst_brk(TBROK, "Invalid ttype value %i", ttype);
		abort();
	}

	

	ret = snprintf(str, size, "%s:%i: ", file, lineno);
	str += ret;
	size -= ret;

	
	ret = snprintf(str, size, "%s: ", res);
	str += ret;
	size -= ret;

	ssize = size - 2;
	ret = vsnprintf(str, size, fmt, va);
	str += MIN(ret, ssize);
	size -= MIN(ret, ssize);
	if (ret >= ssize) {
		tst_res_(file, lineno, TWARN,
				"Next message is too long and truncated:");
	} else if (str_errno) {
		ssize = size - 2;
		ret = snprintf(str, size, ": %s (%d)", str_errno, int_errno);
		str += MIN(ret, ssize);
		size -= MIN(ret, ssize);
		if (ret >= ssize)
			tst_res_(file, lineno, TWARN,
				"Next message is too long and truncated:");
	}

	snprintf(str, size, "\n");

	/* we might be called from signal handler, so use write() */
	buflen = str - buf + 1;
	str = buf;
	while (buflen) {
		ret = write(STDERR_FILENO, str, buflen);
		if (ret <= 0)
			break;

		str += ret;
		buflen -= ret;
	}
}



static void do_exit(int ret)
{
	if (results) {
		if (results->passed && ret == TCONF)
			ret = 0;

		if (results->failed) {
			ret |= TFAIL;
			//print_failure_hints();
		}

		if (results->skipped && !results->passed)
			ret |= TCONF;

		if (results->warnings)
			ret |= TWARN;

		if (results->broken)
			ret |= TBROK;

		fprintf(stderr, "\nSummary:\n");
		fprintf(stderr, "passed   %d\n", results->passed);
		fprintf(stderr, "failed   %d\n", results->failed);
		fprintf(stderr, "broken   %d\n", results->broken);
		fprintf(stderr, "skipped  %d\n", results->skipped);
		fprintf(stderr, "warnings %d\n", results->warnings);
	}

	do_cleanup();

	exit(ret);
}

static void update_results(int ttype)
{
	if (!results)
		return;

	switch (ttype) {
	case TCONF:
		results->skipped++;
	break;
	case TPASS:
		results->passed++;
	break;
	case TWARN:
		results->warnings++;
	break;
	case TFAIL:
		results->failed++;
	break;
	case TBROK:
		results->broken++;
	break;
	}
}

void tst_vres_(const char *file, const int lineno, int ttype,
               const char *fmt, va_list va)
{
	print_result(file, lineno, ttype, fmt, va);

	update_results(TTYPE_RESULT(ttype));
}

void tst_res_(const char *file, const int lineno, int ttype,
              const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	tst_vres_(file, lineno, ttype, fmt, va);
	va_end(va);
}

void tst_vbrk_(const char *file, const int lineno, int ttype,
               const char *fmt, va_list va);

static void (*tst_brk_handler)(const char *file, const int lineno, int ttype,
			       const char *fmt, va_list va) = tst_vbrk_;



static void tst_cvres(const char *file, const int lineno, int ttype,
		      const char *fmt, va_list va)
{
	if (TTYPE_RESULT(ttype) == TBROK) {
		ttype &= ~TTYPE_MASK;
		ttype |= TWARN;
	}

	print_result(file, lineno, ttype, fmt, va);
	update_results(TTYPE_RESULT(ttype));
}


static void do_test_cleanup(void)
{
	tst_brk_handler = tst_cvres;

	if (tst_test->cleanup)
		tst_test->cleanup();


	tst_brk_handler = tst_vbrk_;
}

void tst_vbrk_(const char *file, const int lineno, int ttype,
               const char *fmt, va_list va)
{
	print_result(file, lineno, ttype, fmt, va);
	update_results(TTYPE_RESULT(ttype));

	/*
	 * The getpid implementation in some C library versions may cause cloned
	 * test threads to show the same pid as their parent when CLONE_VM is
	 * specified but CLONE_THREAD is not. Use direct syscall to avoid
	 * cleanup running in the child.
	 */
	if (getpid() == main_pid)
		do_test_cleanup();

	if (getpid() == lib_pid)
		do_exit(TTYPE_RESULT(ttype));

	exit(TTYPE_RESULT(ttype));
}

void tst_brk_(const char *file, const int lineno, int ttype,
              const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	tst_brk_handler(file, lineno, ttype, fmt, va);
	va_end(va);
}


static void do_cleanup(void)
{
	cleanup_ipc();
}



static void do_test_setup(void)
{
	main_pid = getpid();

	// if (!tst_test->all_filesystems && tst_test->skip_filesystems) {
	// 	long fs_type = tst_fs_type(".");
	// 	const char *fs_name = tst_fs_type_name(fs_type);

	// 	if (tst_fs_in_skiplist(fs_name, tst_test->skip_filesystems)) {
	// 		tst_brk(TCONF, "%s is not supported by the test",
	// 			fs_name);
	// 	}

	// 	tst_res(TINFO, "%s is supported by the test", fs_name);
	// }

	// if (tst_test->caps)
	// 	tst_cap_setup(tst_test->caps, TST_CAP_REQ);

	if (tst_test->setup)
		tst_test->setup();

	if (main_pid != getpid())
		tst_brk(TBROK, "Runaway child in setup()!");

	// if (tst_test->caps)
	// 	tst_cap_setup(tst_test->caps, TST_CAP_DROP);
}




static void check_child_status(pid_t pid, int status)
{
	int ret;

	if (WIFSIGNALED(status)) {
		tst_brk(TBROK, "Child (%i) killed by signal %s",
		        pid, WTERMSIG(status));
	}

	if (!(WIFEXITED(status)))
		tst_brk(TBROK, "Child (%i) exited abnormally", pid);

	ret = WEXITSTATUS(status);
	switch (ret) {
	case TPASS:
	case TBROK:
	case TCONF:
	break;
	default:
		tst_brk(TBROK, "Invalid child (%i) exit value %i", pid, ret);
	}
}

void tst_reap_children(void)
{
	int status;
	pid_t pid;

	for (;;) {
		pid = wait(&status);

		if (pid > 0) {
			check_child_status(pid, status);
			continue;
		}

		if (errno == ECHILD)
			break;

		if (errno == EINTR)
			continue;

		tst_brk(TBROK | TERRNO, "wait() failed");
	}
}


static void run_tests(void)
{
	unsigned int i;
	struct results saved_results;
	printf("run_tests now start\n");
	
		//saved_results = *results;
		printf("test execute\n");
		tst_test->test_all();

		if (getpid() != main_pid) {
			exit(0);
		}
		printf("reap child \n");
		tst_reap_children();

		//if (results_equal(&saved_results, results))
		//	tst_brk(TBROK, "Test haven't reported results!");
		return;
	

	for (i = 0; i < tst_test->tcnt; i++) {
		printf("test execute\n");
		saved_results = *results;
		tst_test->test(i);

		if (getpid() != main_pid) {
			exit(0);
		}

		tst_reap_children();

		//if (results_equal(&saved_results, results))
		//	tst_brk(TBROK, "Test %i haven't reported results!", i);
	}
}


static void testrun(void)
{
	unsigned int i = 0;
	unsigned long long stop_time = 0;
	int cont = 1;
	
	do_test_setup();

	printf("testrun start\n");
	run_tests();
		
	

	do_test_cleanup();
	exit(0);
}

static pid_t test_pid;

static int fork_testrun(void)
{
	int status;

	
	printf("fork_testrun start\n");
	test_pid = fork();
	if (test_pid < 0)
		tst_brk(TBROK | TERRNO, "fork()");

	if (!test_pid) {
		testrun();
	}

	waitpid(test_pid, &status, 0);
	alarm(0);
	signal(SIGINT, SIG_DFL);

	

	if (tst_test->forks_child && kill(-test_pid, SIGKILL) == 0)
		tst_res(TINFO, "Killed the leftover descendant processes");

	return 0;
}

unsigned int tst_variant;

void tst_run_tcases(int argc, char *argv[], struct tst_test *self)
{
	int ret = 0;
	unsigned int test_variants = 1;

	lib_pid = getpid();
	tst_test = self;
	do_setup(argc, argv);


	printf("tst_run_tcases start\n");
	if (tst_test->test_variants)
		test_variants = tst_test->test_variants;

	for (tst_variant = 0; tst_variant < test_variants; tst_variant++) {
		ret |= fork_testrun();
		goto exit;
	}

exit:
	do_exit(ret);
}
