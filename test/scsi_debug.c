#define _GNU_SOURCE 1
#include "cmocka-inc.h"
#include <ioc-util.h>
#include <ioc.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "scsi-debug.h"
#include <kmod/libkmod.h>

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

struct kmod_ctx *
__real_kmod_new(const char *dirname,
		const char *const *config_paths);

/*
 * Library will call kmod_new() only once until sdbg_release() is called.
 * We need to avoid expecting more calls.
 */
static struct kmod_ctx *__current_ctx;
struct kmod_ctx *
__wrap_kmod_new(const char *dirname,
		const char *const *config_paths)
{
	void *ptr;

	check_expected_ptr(dirname);
	check_expected_ptr(config_paths);
	ptr = mock_ptr_type(void *);
	if (ptr == WRAP_USE_REAL_PTR) {
		__current_ctx = ptr;
		ptr = __real_kmod_new(dirname, config_paths);
	} else
		__current_ctx = ptr;
	return ptr;
}

static void call_kmod_new(struct kmod_ctx *kmod_new_rv)
{
	if (__current_ctx != NULL)
		return;
	expect_value(__wrap_kmod_new, dirname, NULL);
	expect_value(__wrap_kmod_new, config_paths, NULL);
	will_return(__wrap_kmod_new, kmod_new_rv);
}

struct kmod_ctx *
__real_kmod_unref(struct kmod_ctx *ctx);

static bool __exiting;
static bool __unref_called_at_exit;

/*
 * cmocka tests don't work at atexit time. This function is
 * registered with atexit(3) to check if sdbg_release() had been
 * called.
 */
void check_atexit(void)
{
	if (__exiting && !__unref_called_at_exit) {
		log(LOG_ERR, "ERROR: kmod_unref not called\n");
		_exit(1);
	}
}

struct kmod_ctx *
__wrap_kmod_unref(struct kmod_ctx *ctx)
{
	struct kmod_ctx *rv;

	if (__exiting) {
		__unref_called_at_exit = true;
		return __real_kmod_unref(ctx);
	}

	check_expected_ptr(ctx);
	rv = mock_ptr_type(struct kmod_ctx *);
	if (rv == WRAP_USE_REAL_PTR)
		rv = __real_kmod_unref(ctx);
	__current_ctx = NULL;
	return rv;
}

static void call_kmod_unref(void)
{
	if (__current_ctx == NULL)
		return;
	expect_not_value(__wrap_kmod_unref, ctx, NULL);
	will_return(__wrap_kmod_unref, __current_ctx);
}

static void call_sdbg_release(void)
{
	call_kmod_unref();
	sdbg_release();
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
	expect_string_or_null(__wrap_kmod_module_new_from_lookup,
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

const char *
__real_kmod_module_get_name(const struct kmod_module *mod);

const char *
__wrap_kmod_module_get_name(const struct kmod_module *mod) {

	const char *rv;

	check_expected_ptr(mod);
	rv = mock_ptr_type(const char *);
	if (rv != WRAP_USE_REAL_PTR)
		return rv;
	return __real_kmod_module_get_name(mod);
};

static void call_kmod_module_get_name(const char *name)
{
	expect_not_value(__wrap_kmod_module_get_name, mod, NULL);
	will_return(__wrap_kmod_module_get_name, name);
}

int
__real_kmod_module_get_initstate(const struct kmod_module *mod);

int
__wrap_kmod_module_get_initstate(const struct kmod_module *mod) {

	int rv;

	check_expected_ptr(mod);
	rv = mock_type(int);
	if (rv != WRAP_USE_REAL)
		return rv;
	return __real_kmod_module_get_initstate(mod);
};

static void call_kmod_module_get_initstate(int rv)
{
	expect_not_value(__wrap_kmod_module_get_initstate, mod, NULL);
	will_return(__wrap_kmod_module_get_initstate, rv);
}

struct kmod_module *
__real_kmod_module_unref(struct kmod_module *mod);

struct kmod_module *
__wrap_kmod_module_unref(struct kmod_module *mod)
{
	struct kmod_module *rv;

	check_expected_ptr(mod);
	rv = mock_ptr_type(struct kmod_module *);
	if (rv != WRAP_USE_REAL_PTR)
		return rv;
	return __real_kmod_module_unref(mod);
}

static void call_kmod_module_unref(struct kmod_module *rv)
{
	expect_not_value(__wrap_kmod_module_unref, mod, NULL);
	will_return(__wrap_kmod_module_unref, rv);
}

int
__real_kmod_module_unref_list(struct kmod_list *list);

int
__wrap_kmod_module_unref_list(struct kmod_list *list)
{
	int rv;

	check_expected_ptr(list);
	rv = mock_type(int);
	if (rv != WRAP_USE_REAL)
		return rv;
	return __real_kmod_module_unref_list(list);
}

static void call_kmod_module_unref_list(int rv, int n_elem)
{
	if (n_elem > 0) {
		expect_not_value(__wrap_kmod_module_unref_list, list, NULL);
		will_return(__wrap_kmod_module_unref_list, rv);
	}
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

	for (i = 0; i < n_elem; i++) {
		int nx = i < n_elem - 1 ? i + 1 : 0;

		arr[i].node.next = &arr[nx].node;
		arr[nx].node.prev = &arr[i].node;
	}
	return (struct kmod_list *)arr;
}

struct mock_is_module_loaded_loop {
	struct kmod_module *get_module_rv;
	const char *get_name_rv;
	int initstate;
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
	/*
	 * Using (void *) here to avoid having to define a type-specific
	 * cleanup function
	 */
	void *_ptr __cleanup__(cleanup_free_voidp) = NULL;

	call_kmod_new(mock->kmod_new_rv);
	if (mock->kmod_new_rv != NULL) {
		struct kmod_list *lst, *iter;
		int i = 0;
		bool found = false;

		/* make sure lst is freed on return */
		_ptr = lst = mock_kmod_list(mock->n_lookup_list);
		call_kmod_module_new_from_lookup(mock->modname,
						 mock->lookup_rv, lst);
		kmod_list_foreach(iter, lst) {
			struct kmod_module *mod;
			const char *name;

			mod = mock->loop_rvs[i].get_module_rv;
			call_kmod_module_get_module(mod);
			if (mod == NULL)
				break;
			name = mock->loop_rvs[i].get_name_rv;
			call_kmod_module_get_name(name);
			/* Assume that in the real case, the names will match */
			if (name == WRAP_USE_REAL_PTR ||
			    !strcmp(name, mock->modname)) {
				int state = mock->loop_rvs[i].initstate;

				call_kmod_module_get_initstate(state);
				found = true;
			};
			call_kmod_module_unref(mod);
			if (found)
				break;
			i++;
		}
		call_kmod_module_unref_list(mock->lookup_rv,
					    mock->n_lookup_list);
	}

	rv = is_module_loaded(mock->modname);
	return rv;
}

/* Error in kmod_new() */
static void test_is_module_loaded_err_new(void **state __attribute__((unused)))
{
	struct mock_is_module_loaded mock = { .modname = mod_name };

	call_sdbg_release();
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): alias = NULL */
static void test_is_module_loaded_bad_name(void **state __attribute__((unused)))
{
	struct mock_is_module_loaded mock = {
		.modname = NULL,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = WRAP_USE_REAL,
	};
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): other */
static void test_is_module_loaded_err_lookup(void **state
					     __attribute__((unused)))
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

/* module found, but different name */
static void test_is_module_loaded_err_mismatch(void **state
					       __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		{
			.get_module_rv = WRAP_DUMMY_PTR,
			.get_name_rv = "%WRONG%"
		},
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};
	assert_int_equal(call_is_module_loaded(&mock), 0);
}

static const struct mock_is_module_loaded_loop mock_imll_wrong = {
	.get_module_rv = WRAP_DUMMY_PTR,
	.get_name_rv = "%WRONG%"
};

static const struct mock_is_module_loaded_loop mock_imll_good = {
	.get_module_rv = WRAP_DUMMY_PTR,
	.get_name_rv = mod_name,
};

/* list of 2 entries, first wrong, 2nd good */
static void test_is_module_loaded_live(void **state __attribute__((unused)))
{
	enum { N_LOOP = 2 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_wrong, mock_imll_good
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[1].initstate = KMOD_MODULE_LIVE;
	assert_int_equal(call_is_module_loaded(&mock), 1);
}

/* list of 2 entries, first wrong, 2nd good but going */
static void test_is_module_loaded_going(void **state __attribute__((unused)))
{
	enum { N_LOOP = 2 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_wrong, mock_imll_good
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[1].initstate = KMOD_MODULE_GOING;
	assert_int_equal(call_is_module_loaded(&mock), 0);
}

/* list of 2 entries, first good, 2nd bad but never looked at */
static void test_is_module_loaded_coming(void **state __attribute__((unused)))
{
	enum { N_LOOP = 2 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_good, mock_imll_wrong,
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[1].initstate = KMOD_MODULE_COMING;
	assert_int_equal(call_is_module_loaded(&mock), 1);
}

/* Invalid init state */
static void test_is_module_loaded_bad_state(void **state
					    __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_good,
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[0].initstate = 1000;
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* Error init state */
static void test_is_module_loaded_err_state(void **state
					    __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_good,
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[0].initstate = -ENODEV;
	assert_int_equal(call_is_module_loaded(&mock), -1);
}

/* ENOENT is "no" */
static void test_is_module_loaded_enoent_state(void **state
					       __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_good,
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[0].initstate = -ENOENT;
	assert_int_equal(call_is_module_loaded(&mock), 0);
}

/* BUILTIN is "yes" */
static void test_is_module_loaded_builtin(void **state __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		mock_imll_good,
	};
	struct mock_is_module_loaded mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};

	loop_rvs[0].initstate = KMOD_MODULE_BUILTIN;
	assert_int_equal(call_is_module_loaded(&mock), 1);
}

static const struct mock_is_module_loaded_loop
real_mock_is_module_loaded_loop = {
	.get_module_rv = WRAP_USE_REAL_PTR,
	.get_name_rv = WRAP_USE_REAL_PTR,
	.initstate = WRAP_USE_REAL,
};

static void test_is_module_loaded_real(void **state)
{
	/* pass n_lookup_list = 1: assume only one module in list */
	enum { N_LOOP = 1 };
	struct mock_is_module_loaded_loop loop_rvs[N_LOOP] = {
		real_mock_is_module_loaded_loop,
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


int
__real_kmod_module_probe_insert_module(struct kmod_module *mod,
				       unsigned int flags,
				       const char *extra_options,
				       int (*run_install)(struct kmod_module *m,
							  const char *cmd, void *data),
				       const void *data,
				       void (*print_action)(struct kmod_module *m,
							    bool install,
							    const char *options));

int
__wrap_kmod_module_probe_insert_module(struct kmod_module *mod,
				       unsigned int flags,
				       const char *extra_options,
				       int (*run_install)(struct kmod_module *m,
							  const char *cmd, void *data),
				       const void *data,
				       void (*print_action)(struct kmod_module *m,
							    bool install,
							    const char *options))
{
	int rv;

	check_expected_ptr(mod);
	check_expected(flags);
	check_expected_ptr(extra_options);
	check_expected_ptr(run_install);
	check_expected_ptr(data);
	check_expected_ptr(print_action);
	rv = mock_type(int);
	if (rv != WRAP_USE_REAL)
		return rv;
	else
		return __real_kmod_module_probe_insert_module(mod, flags,
							      extra_options,
							      run_install, data,
							      print_action);
}

static void call_kmod_module_probe_insert_module(int rv)
{
	expect_not_value(__wrap_kmod_module_probe_insert_module, mod, NULL);
	expect_value(__wrap_kmod_module_probe_insert_module,
		     flags, KMOD_PROBE_IGNORE_COMMAND);
	expect_value(__wrap_kmod_module_probe_insert_module,
		     extra_options, NULL);
	expect_value(__wrap_kmod_module_probe_insert_module, run_install, NULL);
	expect_value(__wrap_kmod_module_probe_insert_module, data, NULL);
	expect_value(__wrap_kmod_module_probe_insert_module,
		     print_action, NULL);
	will_return(__wrap_kmod_module_probe_insert_module, rv);
}

struct mock_load_module_loop {
	struct kmod_module *get_module_rv;
	const char *get_name_rv;
};

struct mock_load_module {
	const char *modname;
	struct kmod_ctx *kmod_new_rv;
	int lookup_rv;
	int n_lookup_list;
	struct mock_load_module_loop *loop_rvs;
	int probe_rv;
};

static int call_load_module(struct mock_load_module *mock)
{
	void *_ptr __cleanup__(cleanup_free_voidp) = NULL;

	call_kmod_new(mock->kmod_new_rv);
	if (mock->kmod_new_rv != NULL) {
		struct kmod_list *lst, *iter;
		int i = 0;

		_ptr = lst = mock_kmod_list(mock->n_lookup_list);
		call_kmod_module_new_from_lookup(mock->modname,
						 mock->lookup_rv, lst);
		kmod_list_foreach(iter, lst) {
			struct kmod_module *mod;
			const char *name;

			mod = mock->loop_rvs[i].get_module_rv;
			call_kmod_module_get_module(mod);
			if (mod == NULL)
				break;
			name = mock->loop_rvs[i].get_name_rv;
			call_kmod_module_get_name(name);
			call_kmod_module_unref(mod);
			if (name == WRAP_USE_REAL_PTR ||
			    !strcmp(name, mock->modname)) {
				call_kmod_module_probe_insert_module(mock->probe_rv);
				break;
			}
			i++;
		}
		call_kmod_module_unref_list(mock->lookup_rv,
					    mock->n_lookup_list);
	}

	return load_module(mock->modname);
}


/* Error in kmod_new() */
static void test_load_module_err_new(void **state __attribute__((unused)))
{
	struct mock_load_module mock = {
		.modname = mod_name,
	};

	/*
	 * Without this, kmod_new() won't be called.
	 * This serves also as a test of calling into scsi-debug after
	 * sdbg_release().
	 */
	call_sdbg_release();
	assert_int_equal(call_load_module(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): alias = NULL */
static void test_load_module_err_bad_name(void **state __attribute__((unused)))
{
	struct mock_load_module mock = {
		.modname = NULL,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = WRAP_USE_REAL,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

/* Error in kmod_module_new_from_lookup(): other */
static void test_load_module_err_lookup(void **state __attribute__((unused)))
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

/* module found, but different name => error */
static void test_load_module_err_mismatch(void **state __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_load_module_loop loop_rvs[N_LOOP] = {
		{
			.get_module_rv = WRAP_DUMMY_PTR,
			.get_name_rv = "%WRONG%"
		},
	};
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
	};
	assert_int_equal(call_load_module(&mock), -1);
}

static const struct mock_load_module_loop mock_lm_wrong = {
	.get_module_rv = WRAP_DUMMY_PTR,
	.get_name_rv = "%WRONG%",
};

static const struct mock_load_module_loop mock_lm_good = {
	.get_module_rv = WRAP_DUMMY_PTR,
	.get_name_rv = mod_name,
};

/* Simple good case */
static void test_load_module_good_1(void **state __attribute__((unused)))
{
	struct mock_load_module_loop loop_rv = mock_lm_good;
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = 1,
		.loop_rvs = &loop_rv,
		.probe_rv = 0,
	};

	assert_int_equal(call_load_module(&mock), 0);
}

/* Two lookup results, 1st good */
static void test_load_module_good_2(void **state __attribute__((unused)))
{
	enum { N_LOOP = 2 };
	struct mock_load_module_loop loop_rvs[N_LOOP] = {
		mock_lm_good, mock_lm_wrong,
	};
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
		.probe_rv = 0,
	};

	assert_int_equal(call_load_module(&mock), 0);
}

/* Two lookup results, 2nd good */
static void test_load_module_good_3(void **state __attribute__((unused)))
{
	enum { N_LOOP = 2 };
	struct mock_load_module_loop loop_rvs[N_LOOP] = {
		mock_lm_wrong, mock_lm_good,
	};
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
		.probe_rv = 0,
	};

	assert_int_equal(call_load_module(&mock), 0);
}

/* Error from kmod_module_probe_insert_module() */
static void test_load_module_probe_err(void **state __attribute__((unused)))
{
	struct mock_load_module_loop loop_rv = mock_lm_good;
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = 1,
		.loop_rvs = &loop_rv,
		.probe_rv = -ENODEV,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

/* Positive retcode (blacklist!?) from kmod_module_probe_insert_module() */
static void test_load_module_probe_blk(void **state __attribute__((unused)))
{
	struct mock_load_module_loop loop_rv = mock_lm_good;
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = 0,
		.n_lookup_list = 1,
		.loop_rvs = &loop_rv,
		.probe_rv = KMOD_PROBE_APPLY_BLACKLIST,
	};

	assert_int_equal(call_load_module(&mock), -1);
}

static const struct mock_load_module_loop real_mock_load_module_loop = {
	.get_module_rv = WRAP_USE_REAL_PTR,
	.get_name_rv = WRAP_USE_REAL_PTR,
};

static void test_load_module_real(void **state __attribute__((unused)))
{
	enum { N_LOOP = 1 };
	struct mock_load_module_loop loop_rvs[N_LOOP] = {
		real_mock_load_module_loop,
	};
	struct mock_load_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.lookup_rv = WRAP_USE_REAL,
		.n_lookup_list = N_LOOP,
		.loop_rvs = loop_rvs,
		.probe_rv = WRAP_USE_REAL,
	};

	assert_int_equal(call_load_module(&mock), 0);
	set_module_loaded(state, true);
}

int
__real_kmod_module_new_from_name(struct kmod_ctx *ctx,
				 const char *name,
				 struct kmod_module **mod);

int
__wrap_kmod_module_new_from_name(struct kmod_ctx *ctx,
				 const char *name,
				 struct kmod_module **mod)
{
	int rv;

	check_expected_ptr(ctx);
	check_expected_ptr(name);
	check_expected_ptr(mod);
	rv = mock_type(int);
	if (rv == 0) {
		*mod = WRAP_DUMMY_PTR;
		return 0;
	} else if (rv != WRAP_USE_REAL)
		return rv;
	else
		return __real_kmod_module_new_from_name(ctx, name, mod);
}

static void call_kmod_module_new_from_name(const char *modname, int rv)
{
	expect_not_value(__wrap_kmod_module_new_from_name, ctx, NULL);
	expect_string_or_null(__wrap_kmod_module_new_from_name, name, modname);
	expect_not_value(__wrap_kmod_module_new_from_name, mod, NULL);
	will_return(__wrap_kmod_module_new_from_name, rv);
}

/*
 * unload_module() may need to retry kmod_module_remove_module().
 * In the mock driver, we have no idea how often. So we must stop
 * mocking after the first attempt.
 */
static unsigned int do_wrap_kmod_module_remove_module;

int
__real_kmod_module_remove_module(struct kmod_module *mod, unsigned int flags);

int
__wrap_kmod_module_remove_module(struct kmod_module *mod, unsigned int flags)
{
	int rv;

	if (do_wrap_kmod_module_remove_module > 0)
		do_wrap_kmod_module_remove_module--;
	else
		return __real_kmod_module_remove_module(mod, flags);

	check_expected_ptr(mod);
	check_expected(flags);
	rv = mock_type(int);
	if (rv != WRAP_USE_REAL)
		return rv;
	else
		return __real_kmod_module_remove_module(mod, flags);
}

static void call_kmod_module_remove_module(int rv)
{
	expect_not_value(__wrap_kmod_module_remove_module, mod, NULL);
	expect_value(__wrap_kmod_module_remove_module, flags, 0);
	will_return(__wrap_kmod_module_remove_module, rv);
}

struct mock_unload_module {
	const char *modname;
	struct kmod_ctx *kmod_new_rv;
	int new_mod_rv;
	int remove_rv;
	/* for mocking retries after -EAGAIN */
	int remove_repeat;
};

static int call_unload_module(struct mock_unload_module *mock)
{
	call_kmod_new(mock->kmod_new_rv);
	if (mock->kmod_new_rv) {
		call_kmod_module_new_from_name(mock->modname, mock->new_mod_rv);
		if (mock->new_mod_rv == 0) {
			call_kmod_module_remove_module(mock->remove_rv);
			call_kmod_module_unref(WRAP_DUMMY_PTR);
		} else if (mock->new_mod_rv == WRAP_USE_REAL &&
			   mock->modname != NULL) {
			int i;

			for (i = 0; i < mock->remove_repeat; i++)
				call_kmod_module_remove_module(-EAGAIN);
			call_kmod_module_remove_module(mock->remove_rv);
			call_kmod_module_unref(WRAP_USE_REAL_PTR);
		}
	}
	/* Reset the do_wrap flag before calling unlad_module() */
	do_wrap_kmod_module_remove_module = 1 + mock->remove_repeat;
	return unload_module(mock->modname);
}

/* Error in kmod_new() */
static void test_unload_module_err_new(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = mod_name,
	};

	call_sdbg_release();
	assert_int_equal(call_unload_module(&mock), -1);
}

/* NULL pointer for module name */
static void test_unload_module_name_null(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = NULL,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
	};

	/* kmod_module_new_from_name returns -ENOENT, which we treat as success */
	assert_int_equal(call_unload_module(&mock), 0);
}

/* Bad value for module name */
static void test_unload_module_name_bad(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = "%BAD%",
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
		.remove_rv = WRAP_USE_REAL,
	};

	/* kmod_module_remove_module returns -ENOENT, which we treat as success */
	assert_int_equal(call_unload_module(&mock), 0);
}

/* Error return from kmod_module_remove_module() */
static void test_unload_module_unload_err(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
		.remove_rv = -EBUSY,
	};

	assert_int_equal(call_unload_module(&mock), -1);
}

/* Bad return value from kmod_module_remove_module() */
static void test_unload_module_unload_bad(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
		.remove_rv = 1000,
	};

	assert_int_equal(call_unload_module(&mock), -1);
}

/*
 * Settings in the following 3 tests must match the retry settings in
 * unload_module(). Default is 1s max wait and retry every 0.1s, thus
 * 9 x -EAGAIN followed by success succeeds, 10 x -EAGAIN fails.
 */

/* Retries ending in good status  */
static void test_unload_module_repeat_good_9(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
		.remove_rv = -ENOENT,
		.remove_repeat = 9,
	};

	assert_int_equal(call_unload_module(&mock), 0);
}

/* Retries exhausted  */
static void test_unload_module_repeat_bad_9(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
		.remove_rv = -EAGAIN,
		.remove_repeat = 9,
	};

	assert_int_equal(call_unload_module(&mock), -1);
}

/* Error return after some retries */
static void test_unload_module_repeat_bad_3(void **state __attribute__((unused)))
{
	struct mock_unload_module mock = {
		.modname = mod_name,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv =  WRAP_USE_REAL,
		.remove_rv = -ENODEV,
		.remove_repeat = 3,
	};

	assert_int_equal(call_unload_module(&mock), -1);
}

static int real_unload_module(const char *modname)
{
	struct mock_unload_module mock = {
		.modname = modname,
		.kmod_new_rv = WRAP_USE_REAL_PTR,
		.new_mod_rv = WRAP_USE_REAL,
		.remove_rv = WRAP_USE_REAL,
	};

	return call_unload_module(&mock);
}

static void test_unload_module_real(void **state __attribute__((unused)))
{
	assert_int_equal(real_unload_module(mod_name), 0);
	set_module_loaded(state, false);
}

static int run_mock_modload_tests(void)
{
	const struct CMUnitTest mock_modload_tests[] = {
		cmocka_unit_test(test_is_module_loaded_err_new),
		cmocka_unit_test(test_is_module_loaded_bad_name),
		cmocka_unit_test(test_is_module_loaded_err_lookup),
		cmocka_unit_test(test_is_module_loaded_empty),
		cmocka_unit_test(test_is_module_loaded_err_mismatch),
		cmocka_unit_test(test_is_module_loaded_live),
		cmocka_unit_test(test_is_module_loaded_going),
		cmocka_unit_test(test_is_module_loaded_coming),
		cmocka_unit_test(test_is_module_loaded_bad_state),
		cmocka_unit_test(test_is_module_loaded_err_state),
		cmocka_unit_test(test_is_module_loaded_enoent_state),
		cmocka_unit_test(test_is_module_loaded_builtin),
		cmocka_unit_test(test_load_module_err_new),
		cmocka_unit_test(test_load_module_err_bad_name),
		cmocka_unit_test(test_load_module_err_lookup),
		cmocka_unit_test(test_load_module_empty),
		cmocka_unit_test(test_load_module_err_mismatch),
		cmocka_unit_test(test_load_module_good_1),
		cmocka_unit_test(test_load_module_good_2),
		cmocka_unit_test(test_load_module_good_3),
		cmocka_unit_test(test_load_module_probe_err),
		cmocka_unit_test(test_load_module_probe_blk),
		cmocka_unit_test(test_unload_module_err_new),
		cmocka_unit_test(test_unload_module_name_null),
		cmocka_unit_test(test_unload_module_name_bad),
		cmocka_unit_test(test_unload_module_unload_err),
		cmocka_unit_test(test_unload_module_unload_bad),
	};

	return cmocka_run_group_tests(mock_modload_tests, NULL, NULL);
}

/*
 * These tests are relatively slow as they will require retries
 * and usleep() calls.
 */
static int run_slow_modload_tests(void)
{
	const struct CMUnitTest slow_modload_tests[] = {
		cmocka_unit_test(test_unload_module_repeat_good_9),
		cmocka_unit_test(test_unload_module_repeat_bad_9),
		cmocka_unit_test(test_unload_module_repeat_bad_3),
	};

	return cmocka_run_group_tests(slow_modload_tests, NULL, NULL);
}

static int real_modload_setup(void **state)
{
	struct sdbg_test_state *st;

	/* Make sure module is unloaded initially */
	if (real_unload_module(mod_name) == -1)
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
	if (real_unload_module(mod_name) == -1)
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

	atexit(check_atexit);
	ioc_init();
	rv += run_mock_modload_tests();
	rv += run_slow_modload_tests();
	rv += run_real_modload_tests();
	__exiting = true;
	return rv;
}
