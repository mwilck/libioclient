/*
 * Copyright (c) 2020 Martin Wilck, SUSE Software Solutions Germany GmbH
 * SPDX-license-identifier: GPL-2.0-or-later
 */

#ifndef _IOC_TEST_UTILS_H
#define _IOC_TEST_UTILS_H
static int __DUMMY;

#define WRAP_USE_REAL ((int) 0xaffedead)
#define WRAP_USE_REAL_PTR ((void *) WRAP_USE_REAL)
#define WRAP_SKIP ((int) 0xdeadaffe)
#define WRAP_SKIP_PTR ((void *) WRAP_SKIP)
#define WRAP_DUMMY_PTR ((void *) &__DUMMY)

#define expect_string_or_null(func, arg, ptr)			\
	do {							\
		const char *__p = (ptr);			\
		if (__p == NULL)				\
			expect_value(func, arg, NULL);		\
		else						\
			expect_string(func, arg, __p);		\
	} while (0);

#endif /* _IOC_TEST_UTILS_H */
