/*
 * Copyright (c) 2020 Martin Wilck, SUSE Software Solutions Germany GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cmocka-inc.h"
#include <ioc.h>
#include <ioc-util.h>

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>


int
__wrap_clock_gettime(clockid_t clk_id,
		     struct timespec *ts __attribute__((unused)))
{
	check_expected(clk_id);
	return 0;
}

int
__wrap_fprintf(FILE *stream __attribute__((unused)),
	       const char *format, ...)
{
	check_expected(format);
	return 0;
}

/* This should match definition in ioc.c */
static const int default_loglevel = LOG_NOTICE > MAX_LOGLEVEL ?
	MAX_LOGLEVEL : LOG_NOTICE;

static void test_log_default(void **state __attribute__((unused)))
{
	unsetenv("LIBIOC_LOGLEVEL");

	libioc_init();

	expect_any(__wrap_clock_gettime, clk_id);
	expect_string(__wrap_fprintf, format, IOC_LOG_TIME_FMT "default");
	log(default_loglevel, "default");

	/* crit and below can't be suppressed */
	expect_any(__wrap_clock_gettime, clk_id);
	expect_string(__wrap_fprintf, format, IOC_LOG_TIME_FMT "crit");
	log(LOG_CRIT, "crit");

	/* This is never printed */
	log(LOG_DEBUG + 2, "not called");
}

static void test_invalid_level(void **state __attribute__((unused)))
{
	char buf[8];
	int old_lvl = __ioc_loglevel;

	snprintf(buf, sizeof(buf), "%s", "bad");
	setenv("LIBIOC_LOGLEVEL", buf, true);
	libioc_init();
	assert_int_equal(__ioc_loglevel, old_lvl);

	snprintf(buf, sizeof(buf), "%d", LOG_EMERG - 1);
	setenv("LIBIOC_LOGLEVEL", buf, true);
	libioc_init();
	assert_int_equal(__ioc_loglevel, old_lvl);

	snprintf(buf, sizeof(buf), "%d", MAX_LOGLEVEL + 1);
	setenv("LIBIOC_LOGLEVEL", buf, true);
	libioc_init();
	assert_int_equal(__ioc_loglevel, old_lvl);

	*buf = '\0';
	setenv("LIBIOC_LOGLEVEL", buf, true);
	libioc_init();
	assert_int_equal(__ioc_loglevel, old_lvl);
}

static void test_log_max(void **state __attribute__((unused)))
{
	char buf[2];

	snprintf(buf, sizeof(buf), "%d", MAX_LOGLEVEL);
	setenv("LIBIOC_LOGLEVEL", buf, true);

	libioc_init();

	expect_value(__wrap_clock_gettime, clk_id, CLOCK_MONOTONIC);
	expect_string(__wrap_fprintf, format, IOC_LOG_TIME_FMT "max");
	log(MAX_LOGLEVEL, "max");
	log(MAX_LOGLEVEL + 1, "not called");
}

static void test_log(void **state __attribute__((unused)))
{
	char buf[2];
	int l;

	for (l = LOG_EMERG; l <= MAX_LOGLEVEL; l++) {
		snprintf(buf, sizeof(buf), "%d", LOG_DEBUG + 1);
		setenv("LIBIOC_LOGLEVEL", buf, true);

		libioc_init();

		expect_any(__wrap_clock_gettime, clk_id);
		expect_string(__wrap_fprintf, format, IOC_LOG_TIME_FMT "lvl");
		log(l, "lvl");
	}
	log(l, "not called");
}

static int testsuite1(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_log_default),
		cmocka_unit_test(test_invalid_level),
		cmocka_unit_test(test_log_max),
		cmocka_unit_test(test_log),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

int main(void)
{
	int ret = 0;
	ret += testsuite1();
	return ret;
}
