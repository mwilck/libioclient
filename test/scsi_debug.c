//#define _GNU_SOURCE 1
#include "cmocka-inc.h"
#include <ioc-util.h>

#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "scsi.h"

int
__wrap_uname(struct utsname *buf)
{
	char *v;

	check_expected_ptr(buf);
	memset(buf, 0, sizeof(*buf));
	v = mock_ptr_type(char *);
	log(LOG_NOTICE, "v=%s\n", v);
	strcpy(buf->release, v);
	return mock_type(int);
}

	char *dir;

static void test_kernel_dir_name(void **state __attribute__((unused)))
{
	const char kdir[] = "/lib/modules/6.0-scsidebug";
	char *dir;

	expect_any(__wrap_uname, buf);
	will_return(__wrap_uname, kdir + sizeof("/lib/modules"));
	will_return(__wrap_uname, 0);
	dir = kernel_dir_name();
	/* log(LOG_NOTICE, "\"%s\"\n", dir); */
	assert_string_equal(kdir, dir);
	free(dir);
}

static int testsuite(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_kernel_dir_name),

	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

int main(void)
{
	int ret = 0;
	ret += testsuite();
	return ret;
}
