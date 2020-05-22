#define _GNU_SOURCE 1
#include "cmocka-inc.h"
#include <ioc-util.h>

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/utsname.h>

#include "scsi.h"

#define WRAP_USE_REAL ((int)0xaffedead)

int
__wrap_uname(struct utsname *buf)
{
	char *v;
	int rc;

	check_expected_ptr(buf);
	memset(buf, 0, sizeof(*buf));

	rc = mock_type(int);
	if (rc == 0) {
		v = mock_ptr_type(char *);
		if (memccpy(buf->release, v, '\0', sizeof(buf->release))
		    == NULL)
			buf->release[sizeof(buf->release) - 1] = '\0';
	} else
		/* This is not a real errno from uname() */
		errno = ENXIO;
	return rc;
}

__attribute__((format(printf, 2, 3))) int
__wrap_asprintf(char **strp, const char *fmt, ...)

{
	int rc;

	check_expected_ptr(strp);
	check_expected_ptr(fmt);

	rc = mock_type(int);
	if (rc == WRAP_USE_REAL) {
		va_list va;

		va_start(va, fmt);
		rc = vasprintf(strp, fmt, va);
		va_end(va);
		return rc;
	} else if (rc == 0) {
		*strp = mock_ptr_type(char *);
		return 0;
	} else
		return rc;
}

static void __call_kernel_dir_name(const char *kdir, int uname_rv, int asp_rv,
				   const char *asp_str, const char *res)
{
	char *dir;

	expect_not_value(__wrap_uname, buf, NULL);
	will_return(__wrap_uname, uname_rv);
	if (uname_rv == 0) {
		will_return(__wrap_uname, kdir + sizeof("/lib/modules"));
		expect_not_value(__wrap_asprintf, strp, NULL);
		expect_string(__wrap_asprintf, fmt, "/lib/modules/%s");
		will_return(__wrap_asprintf, asp_rv);
		if (asp_rv == 0)
			/* returned string will be free()d */
			will_return(__wrap_asprintf, strdup(asp_str));
	}
	dir = kernel_dir_name();
	if (res == NULL)
		assert_null(dir);
	else
		assert_string_equal(res, dir);
	free(dir);
}

static const char kdir[] = "/lib/modules/6.0-scsidebug";

/* 1. Good case, mocked */
static void test_kernel_dir_name1(void **state __attribute__((unused)))
{
	__call_kernel_dir_name(kdir, 0, 0, kdir, kdir);
}

/* 2. Good case, calling real vasprintf */
static void test_kernel_dir_name2(void **state __attribute__((unused)))
{
	__call_kernel_dir_name(kdir, 0, WRAP_USE_REAL, NULL, kdir);
}

/* 3. Error in uname() */
static void test_kernel_dir_name3(void **state __attribute__((unused)))
{
	__call_kernel_dir_name(kdir, -1, 0, NULL, NULL);
}

/* 4. Error in asprintf() */
static void test_kernel_dir_name4(void **state __attribute__((unused)))
{
	__call_kernel_dir_name(kdir, 0, -1, NULL, NULL);
}

static const char modname[] = "scsi_debug";
static void test_is_module_loaded1(void **state __attribute__((unused)))
{
	int rc = is_module_loaded(modname);

	/* log(LOG_NOTICE, "module %s: %d (%s)\n", modname, rc,
	   rc < 0 ? strerror(-rc) : ""); */
	assert_int_equal(rc, 0);
}

static void test_is_module_loaded2(void **state __attribute__((unused)))
{
	int rc = is_module_loaded(modname);

	/* log(LOG_NOTICE, "module %s: %d (%s)\n", modname, rc,
	   rc < 0 ? strerror(-rc) : ""); */
	assert_int_equal(rc, 1);
}

static void test_load_module1(void **state __attribute__((unused)))
{
	int rc = load_module(modname);

	/* log(LOG_NOTICE, "module %s: %d\n", modname, rc); */
	assert_int_equal(rc, 0);
}

static void test_unload_module1(void **state __attribute__((unused)))
{
	int rc = unload_module(modname);

	/* log(LOG_NOTICE, "module %s: %d\n", modname, rc); */
	assert_int_equal(rc, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_kernel_dir_name1),
		cmocka_unit_test(test_kernel_dir_name2),
		cmocka_unit_test(test_kernel_dir_name3),
		cmocka_unit_test(test_kernel_dir_name4),
		cmocka_unit_test(test_is_module_loaded1),
		cmocka_unit_test(test_load_module1),
		cmocka_unit_test(test_is_module_loaded2),
		cmocka_unit_test(test_unload_module1),
		cmocka_unit_test(test_is_module_loaded1),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
