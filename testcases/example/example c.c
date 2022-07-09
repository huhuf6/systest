#include<stdlib.h>
#include <errno.h>
#include "test.h"

#define ENV1 "LTP_TEST_ENV"
#define ENV2 "LTP_TEST_THIS_DOES_NOT_EXIST"
#define ENV_VAL "val"

static void setup(void)
{
	if (setenv(ENV1, ENV_VAL, 1))
		tst_brk(TBROK | TERRNO, "setenv() failed");
}

static void mytest(void)
{
	char *ret;

	ret = getenv(ENV1);

	if (!ret) {
		tst_res(TFAIL, "getenv(" ENV1 ") = NULL");
		goto next;
	}

	if (!strcmp(ret, ENV_VAL)) {
		tst_res(TPASS, "getenv(" ENV1 ") = '"ENV_VAL "'");
	} else {
		tst_res(TFAIL, "getenv(" ENV1 ") = '%s', expected '"
		               ENV_VAL "'", ret);
	}

next:
	ret = getenv(ENV2);

	if (ret)
		tst_res(TFAIL, "getenv(" ENV2 ") = '%s'", ret);
	else
		tst_res(TPASS, "getenv(" ENV2 ") = NULL");
}

static struct tst_test test = {
	.test_all = mytest,
	.setup = setup,
};
