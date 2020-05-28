#define _GNU_SOURCE 1
#include <ioc-util.h>

#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <kmod/libkmod.h>

static void cleanup_kmod_module(struct kmod_module **mod)
{
	if (mod && *mod)
		kmod_module_unref(*mod);
}

static void cleanup_kmod_list(struct kmod_list **lst)
{
	if (lst && *lst)
		kmod_module_unref_list(*lst);
}

static struct kmod_ctx *__my_ctx;

static void put_kmod_ctx(void)
{
	if (__my_ctx)
		kmod_unref(__my_ctx);
	__my_ctx = NULL;
}

void sdbg_release(void)
{
	put_kmod_ctx();
}

static void install_atexit_handler(void)
{
#if __GLIBC_PREREQ(2, 3)
	static bool atexit_called;

	if (atexit_called)
		return;
	atexit_called = true;
	atexit(sdbg_release);
#endif
}

static struct kmod_ctx *get_kmod_ctx(void)
{
	if (__my_ctx == NULL) {
		install_atexit_handler();
		__my_ctx = kmod_new(NULL, NULL);
	}
	return __my_ctx;
}

static int lookup_module(struct kmod_ctx *ctx, const char *name,
			 struct kmod_list **lst)
{
	int rc;

	rc = kmod_module_new_from_lookup(ctx, name, lst);
	if (rc < 0) {
		log(LOG_ERR, "kmod_module_new_from_lookup (%s): %s\n",
		    name, strerror(-rc));
		errno = -rc;
		return -1;
	} else if (*lst == NULL) {
		log(LOG_ERR, "kmod_module_new_from_lookup (%s): not found\n",
		    name);
		errno = ENOENT;
		return -1;
	}
	return rc;
}

static bool real_name_matches(const char *real_name, const char *name)
{
	if (strncmp(name, real_name, PATH_MAX)) {
		log(LOG_DEBUG, "name mismatch: \"%s\" != \"%s\"\n",
		    name, real_name);
		return false;
	} else
		return true;
}

static void log_error_or_unexpected(const char *func, const char *modname,
				    int rc)
{
	if (rc < 0) {
		errno = -rc;
		log(LOG_ERR, "%s (%s): %s\n", func, modname, strerror(errno));
	} else {
		errno = EINVAL;
		log(LOG_ERR, "%s (%s): unexpected return value %d\n",
		    func, modname, rc);
	}
}

int is_module_loaded(const char *name)
{
	struct kmod_ctx *ctx;
	struct kmod_list *lst __cleanup__(cleanup_kmod_list) = NULL;
	struct kmod_list *iter;
	int rc;

	ctx = get_kmod_ctx();
	if (!ctx)
		return -1;

	rc = lookup_module(ctx, name, &lst);
	if (rc == -1)
		return rc;

	rc = 0;
	kmod_list_foreach(iter, lst) {
		struct kmod_module *mod
			__cleanup__(cleanup_kmod_module) = NULL;
		int state;
		const char *real_name;

		mod = kmod_module_get_module(iter);
		if (!mod) {
			/*
			 * In current kmod code (kmod-27), this can't happen
			 * unless iter itself is NULL, in which case the loop
			 * would have been exited.
			 */
			rc = -1;
			errno = EINVAL;
			log(LOG_ERR, "invalid module in kmod list\n");
			break;
		}
		real_name = kmod_module_get_name(mod);
		/* kmod_module_new_from_lookup() may have matched by alias */
		if (!real_name_matches(real_name, name))
			continue;
		state = kmod_module_get_initstate(mod);
		switch(state) {
		case KMOD_MODULE_BUILTIN:
		case KMOD_MODULE_LIVE:
		case KMOD_MODULE_COMING:
			return 1;
		case -ENOENT:
		case KMOD_MODULE_GOING:
			break;
		default:
			log_error_or_unexpected("kmod_module_get_initstate",
						real_name, state);
			return -1;
		}
		log(LOG_DEBUG, "module \"%s\" initstate %d\n",
		    real_name, state);
		if (rc != 0)
			break;
	}
	return rc;
}

int load_module(const char *name)
{
	struct kmod_ctx *ctx;
	struct kmod_list *lst __cleanup__(cleanup_kmod_list) = NULL;
	struct kmod_list *iter;
	int rc;

	ctx = get_kmod_ctx();
	if (!ctx)
		return -1;

	rc = lookup_module(ctx, name, &lst);
	if (rc == -1)
		return rc;

	rc = -1;
	kmod_list_foreach(iter, lst) {
		struct kmod_module *mod
			__cleanup__(cleanup_kmod_module) = NULL;
		const char *real_name;

		mod = kmod_module_get_module(iter);
		if (!mod) {
			rc = -1;
			errno = EINVAL;
			log(LOG_ERR, "invalid module in kmod list\n");
			break;
		}
		real_name = kmod_module_get_name(mod);
		if (!real_name_matches(real_name, name))
			continue;

		rc = kmod_module_probe_insert_module(mod,
						     KMOD_PROBE_IGNORE_COMMAND,
						     NULL, NULL, NULL, NULL);
		if (rc == 0)
			return 0;
		else {
			log_error_or_unexpected("kmod_module_insert_module",
						real_name, rc);
			return -1;
		}
	}
	if (rc == -1) {
		log(LOG_ERR, "module \"%s\" not found\n", name);
		errno = ENOENT;
	}
	return rc;
}

int unload_module(const char *name)
{
	struct kmod_ctx *ctx;
	struct kmod_module *mod __cleanup__(cleanup_kmod_module) = NULL;
	int rc;
	uint64_t start;
	int64_t remain;
	static const uint64_t LIMIT = 1000000LU;
	static const useconds_t SLEEP = LIMIT/10;

	ctx = get_kmod_ctx();
	if (!ctx)
		return -1;

	rc = kmod_module_new_from_name(ctx, name, &mod);
	if (rc == -ENOENT)
		return 0;
	else if (rc < 0) {
		log(LOG_ERR, "kmod_module_new_from_name (%s): %s\n",
		    name, strerror(-rc));
		return -1;
	}

	for (start = now_us(), remain = LIMIT; remain > 0;
	     remain = start + LIMIT - now_us()) {
		rc = kmod_module_remove_module(mod, 0);
		if (rc == -ENOENT || rc == 0)
			return 0;
		else if (rc == -EAGAIN)
			usleep(remain <= SLEEP ? remain : SLEEP);
		else {
			log_error_or_unexpected("kmod_module_remove_module",
						name, rc);
			return -1;
		}
	}
	log(LOG_ERR, "timeout removing %s after %"PRIu64"ms\n",
	    name, (now_us() - start) / 1000);
	errno = EBUSY;
	return -1;
}
