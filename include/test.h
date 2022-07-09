#ifndef TEST_H__
#define TEST_H__


#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifndef TST_RES_FLAGS_H
#define TST_RES_FLAGS_H

/* Use low 6 bits to encode test type */
#define TTYPE_MASK	0x3f
#define TPASS	0	/* Test passed flag */
#define TFAIL	1	/* Test failed flag */
#define TBROK	2	/* Test broken flag */
#define TWARN	4	/* Test warning flag */
#define TINFO	16	/* Test information flag */
#define TCONF	32	/* Test not appropriate for configuration flag */
#define TTYPE_RESULT(ttype)	((ttype) & TTYPE_MASK)

#define TERRNO	0x100	/* Append errno information to output */
#define TTERRNO	0x200	/* Append TEST_ERRNO information to output */
#define TRERRNO	0x400	/* Capture errno information from TEST_RETURN to output; useful for pthread-like APIs :). */

#endif /* TST_RES_FLAGS_H */

#define TST_BUILD_BUG_ON(condition) \
	do { ((void)sizeof(char[1 - 2 * !!(condition)])); } while (0)


#define TST_BRK_SUPPORTS_ONLY_TCONF_TBROK(condition) \
	TST_BUILD_BUG_ON(condition)

#ifndef MIN
# define MIN(a, b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})
#endif /* MIN */

#ifndef MAX
# define MAX(a, b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; \
})
#endif /* MAX */

struct tst_test {
	/* number of tests available in test() function */
	unsigned int tcnt;

	
	/*
	 * The supported_archs is a NULL terminated list of archs the test
	 * does support.
	 */
	const char *const *supported_archs;

	/* If set the test is compiled out */
	const char *tconf_msg;

	int needs_tmpdir:1;
	int needs_root:1;
	int forks_child:1;
	int needs_device:1;
	int needs_checkpoints:1;
	int needs_overlay:1;
	int format_device:1;
	int mount_device:1;
	int needs_rofs:1;
	int child_needs_reinit:1;
	int needs_devfs:1;
	int restore_wallclock:1;
	/*
	 * If set the test function will be executed for all available
	 * filesystems and the current filesytem type would be set in the
	 * tst_device->fs_type.
	 *
	 * The test setup and cleanup are executed before/after __EACH__ call
	 * to the test function.
	 */
	int all_filesystems:1;
	int skip_in_lockdown:1;
	int skip_in_compat:1;


	/*
	 * If set non-zero denotes number of test variant, the test is executed
	 * variants times each time with tst_variant set to different number.
	 *
	 * This allows us to run the same test for different settings. The
	 * intended use is to test different syscall wrappers/variants but the
	 * API is generic and does not limit the usage in any way.
	 */
	unsigned int test_variants;

	/* Minimal device size in megabytes */
	unsigned int dev_min_size;

	/* Device filesystem type override NULL == default */
	const char *dev_fs_type;

	/* Options passed to SAFE_MKFS() when format_device is set */
	const char *const *dev_fs_opts;
	const char *const *dev_extra_opts;

	/* Device mount options, used if mount_device is set */
	const char *mntpoint;
	unsigned int mnt_flags;
	void *mnt_data;

	/* override default timeout per test run, disabled == -1 */
	int timeout;

	void (*setup)(void);
	void (*cleanup)(void);

	void (*test)(unsigned int test_nr);
	void (*test_all)(void);

	/* Syscall name used by the timer measurement library */
	const char *scall;

	/* Sampling function for timer measurement testcases */
	int (*sample)(int clk_id, long long usec);

	/* NULL terminated array of resource file names */
	const char *const *resource_files;

	/* NULL terminated array of needed kernel drivers */
	const char * const *needs_drivers;

	/*
	 * NULL terminated array of (/proc, /sys) files to save
	 * before setup and restore after cleanup
	 */
	const char * const *save_restore;

	/*
	 * NULL terminated array of kernel config options required for the
	 * test.
	 */
	const char *const *needs_kconfigs;

	/*
	 * NULL-terminated array to be allocated buffers.
	 */
	struct tst_buffers *bufs;

	/*
	 * NULL-terminated array of capability settings
	 */
	struct tst_cap *caps;

	/*
	 * {NULL, NULL} terminated array of tags.
	 */
	const struct tst_tag *tags;

	/* NULL terminated array of required commands */
	const char *const *needs_cmds;


	/* {} terminated array of required CGroup controllers */
	const char *const *needs_cgroup_ctrls;
};



/*
 * Reports testcase result.
 */
void tst_res_(const char *file, const int lineno, int ttype,
              const char *fmt, ...)
              __attribute__ ((format (printf, 4, 5)));

#define tst_res(ttype, arg_fmt, ...) \
	({									\
		TST_BUILD_BUG_ON(!((TTYPE_RESULT(ttype) ?: TCONF) & \
			(TCONF | TFAIL | TINFO | TPASS | TWARN))); 				\
		tst_res_(__FILE__, __LINE__, (ttype), (arg_fmt), ##__VA_ARGS__);\
	})


void tst_brk_(const char *file, const int lineno, int ttype,
              const char *fmt, ...)
              __attribute__ ((format (printf, 4, 5)));

#define tst_brk(ttype, arg_fmt, ...)						\
	({									\
		TST_BRK_SUPPORTS_ONLY_TCONF_TBROK(!((ttype) &			\
			(TBROK | TCONF | TFAIL))); 				\
		tst_brk_(__FILE__, __LINE__, (ttype), (arg_fmt), ##__VA_ARGS__);\
	})



void tst_run_tcases(int argc, char *argv[], struct tst_test *self)
                    __attribute__ ((noreturn));

#ifndef TST_NO_DEFAULT_MAIN

static struct tst_test test;

int main(int argc, char *argv[])
{
	printf("main start\n");
	tst_run_tcases(argc, argv, &test);
}

#endif /* TST_NO_DEFAULT_MAIN */
#endif
