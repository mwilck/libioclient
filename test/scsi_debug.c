#define _GNU_SOURCE 1
#include "cmocka-inc.h"
#include <ioc-util.h>
#include <ioc.h>

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/utsname.h>

#include "scsi-debug.h"
#include <kmod/libkmod.h>

#define WRAP_USE_REAL ((int) 0xaffedead)
#define WRAP_USE_REAL_PTR ((void *) WRAP_USE_REAL)
#define WRAP_SKIP ((int) 0xdeadaffe)
#define WRAP_SKIP_PTR ((void *) WRAP_SKIP)

struct sdbg_test_state {
	bool module_loaded;
};

static const char mod_name[] = "scsi_debug";
//static const char mod_name[] = "tcm_qla2xxx";

static bool test_module_loaded(void **state)
{
	return ((struct sdbg_test_state *) *state)->module_loaded;
}

static void set_module_loaded(void **state, bool loaded)
{
	((struct sdbg_test_state *) *state)->module_loaded = loaded;
}

static void cleanup_fclose(FILE **f)
{
	if (f && *f)
		fclose(*f);
}

static void cleanup_free_charp(char **p)
{
	if (p)
		free(*p);
}

static void cleanup_free_voidp(void **p)
{
	if (p)
		free(*p);
}

static int check_proc_modules(const char *modname)
{
	static const char path[] = "/proc/modules";
	FILE *proc_modules __cleanup__(cleanup_fclose) = NULL;
	char *line __cleanup__(cleanup_free_charp) = NULL;
	size_t len;
	ssize_t nread, namelen;

	proc_modules = fopen(path, "r");
	if (proc_modules == NULL) {
		log(LOG_ERR, "fopen(%s): %m\n", path);
		return -1;
	}

	namelen = strlen(modname);
	while ((nread = getline(&line, &len, proc_modules)) != -1) {
		if (nread > namelen && !strncmp(modname, line, namelen) &&
		    line[namelen] == ' ')
			return 1;
	};

	return 0;
}

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

static void call_kernel_dir_name(const char *kdir, int uname_rv, int asp_rv,
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
	call_kernel_dir_name(kdir, 0, 0, kdir, kdir);
}

/* 2. Good case, calling real vasprintf */
static void test_kernel_dir_name2(void **state __attribute__((unused)))
{
	call_kernel_dir_name(kdir, 0, WRAP_USE_REAL, NULL, kdir);
}

/* 3. Error in uname() */
static void test_kernel_dir_name3(void **state __attribute__((unused)))
{
	call_kernel_dir_name(kdir, -1, 0, NULL, NULL);
}

/* 4. Error in asprintf() */
static void test_kernel_dir_name4(void **state __attribute__((unused)))
{
	call_kernel_dir_name(kdir, 0, -1, NULL, NULL);
}


struct kmod_ctx *
__real_kmod_new(const char *dirname,
		const char *const *config_paths);

struct kmod_ctx *
__wrap_kmod_new(const char *dirname,
		const char *const *config_paths)
{
	void *ptr;

	check_expected_ptr(dirname);
	check_expected_ptr(config_paths);
	ptr = mock_ptr_type(void *);
	if (ptr == WRAP_USE_REAL_PTR)
		return __real_kmod_new(dirname, config_paths);
	else
		return ptr;
}

static void call_kmod_new(struct kmod_ctx *kmod_new_rv)
{
	expect_value(__wrap_kmod_new, dirname, NULL);
	expect_value(__wrap_kmod_new, config_paths, NULL);
	will_return(__wrap_kmod_new, kmod_new_rv);
}

int
__real_kmod_module_new_from_lookup(struct kmod_ctx *ctx,
				   const char *given_alias,
				   struct kmod_list **list);

int
__wrap_kmod_module_new_from_lookup(struct kmod_ctx *ctx,
				   const char *given_alias,
				   struct kmod_list **list)
{
	int rv;

	check_expected_ptr(ctx);
	check_expected_ptr(given_alias);
	check_expected_ptr(list);
	assert_ptr_equal(*list, NULL);

	rv = mock_type(int);
	if (rv == 0)
		*list = mock_ptr_type(void *);
	if (rv != WRAP_USE_REAL)
		return rv;
	return __real_kmod_module_new_from_lookup(ctx, given_alias, list);
}

static void call_kmod_module_new_from_lookup(const char *modname, int lookup_rv,
					     void *lookup_list)
{
	expect_not_value(__wrap_kmod_module_new_from_lookup, ctx, NULL);
	if (modname == NULL)
		expect_value(__wrap_kmod_module_new_from_lookup,
			     given_alias, NULL);
	else
		expect_string(__wrap_kmod_module_new_from_lookup,
			      given_alias, modname);
	expect_not_value(__wrap_kmod_module_new_from_lookup, list,
			 NULL);

	will_return(__wrap_kmod_module_new_from_lookup, lookup_rv);
	if (lookup_rv == 0)
		will_return(__wrap_kmod_module_new_from_lookup, lookup_list);
}


struct kmod_module *
__real_kmod_module_get_module(const struct kmod_list *entry);

struct kmod_module *
__wrap_kmod_module_get_module(const struct kmod_list *entry)
{
	struct kmod_module *rv;

	check_expected_ptr(entry);
	rv = mock_ptr_type(struct kmod_module *);
	if (rv != WRAP_USE_REAL_PTR)
		return rv;
	return __real_kmod_module_get_module(entry);
}

static void call_kmod_module_get_module(struct kmod_module *get_module_rv)
{
	if (get_module_rv == WRAP_SKIP_PTR)
		return;
	expect_not_value(__wrap_kmod_module_get_module, entry, NULL);
	will_return(__wrap_kmod_module_get_module, get_module_rv);
}

/*
 * Copied verbatim from kmod-27.
 * This will fail if the kmod internal structures change.
 * Tell me how else to fake this.
 */
struct __kmod_list_node {
	struct __kmod_list_node *next, *prev;
};

struct __kmod_list {
	struct __kmod_list_node node;
	void *data;
};

static struct kmod_list *mock_kmod_list(int n_elem)
{
	struct __kmod_list *arr;
	int i;

	if (n_elem <= 0)
		return NULL;
	arr = calloc(n_elem, sizeof(*arr));
	assert_non_null(arr);
	for (i = 0; i < n_elem - 1; i++) {
		arr[i].node.next = &arr[i + 1].node;
		arr[i+1].node.prev = &arr[i].node;
	}
	return (struct kmod_list*)arr;
}

struct mock_is_module_loaded_loop {
	struct kmod_module *get_module_rv;
};

struct mock_is_module_loaded {
	const char *modname;
	struct kmod_ctx *kmod_new_rv;
	int lookup_rv;
	int n_lookup_list;
	struct mock_is_module_loaded_loop *loop_rvs;
};

static int call_is_module_loaded(struct mock_is_module_loaded *mock)
{
	int rv;

	call_kmod_new(mock->kmod_new_rv);
	if (mock->kmod_new_rv != NULL) {
		/*
		 * Using (void *) here to avoid having to define a type-specific
		 * cleanup function
		 */
		void *_ptr __cleanup__(cleanup_free_voidp) = NULL;
		struct kmod_list *lst, *iter;
		int i = 0;

		/* make sure lst is freed on return */
		_ptr = lst = mock_kmod_list(mock->n_lookup_list);
		call_kmod_module_new_from_lookup(mock->modname,
						 mock->lookup_rv, lst);
		kmod_list_foreach(iter, lst) {
			struct kmod_module *mod;
			mod = mock->loop_rvs[i].get_module_rv;
			call_kmod_module_get_module(mod);
			if (mod == NULL)
				break;
		}
	}

	rv = is_module_loaded(mock->modname);
	return rv;
}

/* Error in kmod_new() */
static void test_is_module_loaded_err_1(void **state __attribute__((unused)))
{
	struct mock_is_module_loaded mock = { .modname = mod_name };

	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): alias = NULL */
static void test_is_module_loaded_err_2(void **state __attribute__((unused)))
{
	struct mock_is_module_loaded mock = {
		.modname = NULL,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = WRAP_USE_REAL,
	};
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): other */
static void test_is_module_loaded_err_3(void **state __attribute__((unused)))
{
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = -ENOMEM,
	};
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* module not found in kmod_module_new_from_lookup() */
static void test_is_module_loaded_empty(void **state __attribute__((unused)))
{
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = 0,
	};
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

static void test_is_module_loaded_real(void **state)
{
	/* pass n_lookup_list = 1: assume only one module in list */
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		{ .get_module_rv = WRAP_USE_REAL_PTR, },
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv =  WRAP_USE_REAL,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};
	int expected = test_module_loaded(state) ? 1 : 0;

	assert_int_equal(check_proc_modules(mod_name), expected);
	assert_int_equal(call_is_module_loaded(&mock), expected);
}

struct mock_load_module_loop {
	struct kmod_module *get_module_rv;
};

struct mock_load_module {
	const char *modname;
	struct kmod_ctx *kmod_new_rv;
	int lookup_rv;
	int n_lookup_list;
	struct mock_load_module_loop *loop_rvs;
};

static int call_load_module(struct mock_load_module *mock)
{
	call_kmod_new(mock->kmod_new_rv);
	if (mock->kmod_new_rv != NULL) {
		/* See call_is_module_loaded */
		void *_ptr __cleanup__(cleanup_free_voidp) = NULL;
		struct kmod_list *lst, *iter;
		int i = 0;

		_ptr = lst = mock_kmod_list(mock->n_lookup_list);
		call_kmod_module_new_from_lookup(mock->modname,
						 mock->lookup_rv, lst);
		kmod_list_foreach(iter, lst) {
			struct kmod_module *mod;

			mod = mock->loop_rvs[i].get_module_rv;
			call_kmod_module_get_module(mod);
			if (mod == NULL)
				break;
		}
	}

	return load_module(mock->modname);
}


/* Error in kmod_new() */
static void test_load_module_err_1(void **state __attribute__((unused)))
{
	struct mock_load_module mock = {
		.modname = mod_name,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): alias = NULL */
static void test_load_module_err_2(void **state __attribute__((unused)))
{
	struct mock_load_module mock = {
		.modname = NULL,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = WRAP_USE_REAL,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): other */
static void test_load_module_err_3(void **state __attribute__((unused)))
{
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = -ENOMEM,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

/* module not found in kmod_module_new_from_lookup() */
static void test_load_module_empty(void **state __attribute__((unused)))
{
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = 0,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

static void test_load_module_real(void **state __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_load_module_loop loop_rvs[N_LOOP] = {
		{ .get_module_rv = WRAP_USE_REAL_PTR, }
	};
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = WRAP_USE_REAL,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	assert_int_equal(call_load_module(&mock), 0);
	set_module_loaded(state, true);
}

static int call_unload_module(const char *modname,
			      struct kmod_ctx *kmod_new_rv)
{
	expect_value(__wrap_kmod_new, dirname, NULL);
	expect_value(__wrap_kmod_new, config_paths, NULL);
	will_return(__wrap_kmod_new, kmod_new_rv);
	return unload_module(modname);
}

/* Error in kmod_new() */
static void test_unload_module_err_1(void **state __attribute__((unused)))
{
	assert_int_equal(call_unload_module(mod_name, NULL), -1);
}

static void test_unload_module_real(void **state __attribute__((unused)))
{
	assert_int_equal(call_unload_module(mod_name, WRAP_USE_REAL_PTR), 0);
	set_module_loaded(state, false);
}

static int run_kernel_dir_name_tests(void)
{
	const struct CMUnitTest kernel_dir_name_tests[] = {
		cmocka_unit_test(test_kernel_dir_name1),
		cmocka_unit_test(test_kernel_dir_name2),
		cmocka_unit_test(test_kernel_dir_name3),
		cmocka_unit_test(test_kernel_dir_name4),
	};

	return cmocka_run_group_tests(kernel_dir_name_tests, NULL, NULL);
}

static int run_mock_modload_tests(void)
{
	const struct CMUnitTest mock_modload_tests[] = {
		cmocka_unit_test(test_is_module_loaded_err_1),
		cmocka_unit_test(test_is_module_loaded_err_2),
		cmocka_unit_test(test_is_module_loaded_err_3),
		cmocka_unit_test(test_is_module_loaded_empty),
		cmocka_unit_test(test_load_module_err_1),
		cmocka_unit_test(test_load_module_err_2),
		cmocka_unit_test(test_load_module_err_3),
		cmocka_unit_test(test_load_module_empty),
		cmocka_unit_test(test_unload_module_err_1),
	};

	return cmocka_run_group_tests(mock_modload_tests, NULL, NULL);
}

static int real_modload_setup(void **state)
{
	struct sdbg_test_state *st;

	/* Make sure module is unloaded initially */
	if (call_unload_module(mod_name, WRAP_USE_REAL_PTR) == -1)
		return -1;
	st = calloc(1, sizeof(*st));
	if (!st)
		return -1;
	*state = st;
	set_module_loaded(state, false);
	return 0;
}

static int real_modload_teardown(void **state)
{
	/* Unload module after test */
	free(*state);
	if (call_unload_module(mod_name, WRAP_USE_REAL_PTR) == -1)
		return -1;
	return 0;
}

static int run_real_modload_tests(void)
{
	const struct CMUnitTest real_modload_tests[] = {
		/* Assume module is not loaded on startup */
		cmocka_unit_test(test_is_module_loaded_real),
		/* Load module, check that it's now loaded */
		cmocka_unit_test(test_load_module_real),
		cmocka_unit_test(test_is_module_loaded_real),
		/* Loading again should succeed with no action */
		cmocka_unit_test(test_load_module_real),
		cmocka_unit_test(test_is_module_loaded_real),
		/* Unload module, and verify */
		cmocka_unit_test(test_unload_module_real),
		cmocka_unit_test(test_is_module_loaded_real),
		/* Unloading again should succeed with no action */
		cmocka_unit_test(test_unload_module_real),
		cmocka_unit_test(test_is_module_loaded_real),
	};

	return cmocka_run_group_tests(real_modload_tests,
				      real_modload_setup,
				      real_modload_teardown);
}

int main(void)
{
	int rv = 0;

	ioc_init();
	rv += run_kernel_dir_name_tests();
	rv += run_mock_modload_tests();
	rv += run_real_modload_tests();
	return rv;
}
