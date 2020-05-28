#define _GNU_SOURCE 1
#include <sys/utsname.h>
#include <ioc-util.h>

#include <limits.h>
#include <errno.h>
#include <string.h>
#include <kmod/libkmod.h>

char *kernel_dir_name(void)
{
	static char *buf;
	struct utsname uts;

	if (uname(&uts) == -1) {
		log(LOG_ERR, "uname: %m\n");
		return NULL;
	}
	if (asprintf(&buf, "/lib/modules/%s", uts.release) == -1)
		return NULL;

	return buf;
}

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

static void cleanup_kmod_ctx(struct kmod_ctx **ctx)
{
	if (ctx && *ctx)
		kmod_unref(*ctx);
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
	struct kmod_ctx *ctx __cleanup__(cleanup_kmod_ctx) = NULL;
	struct kmod_list *lst __cleanup__(cleanup_kmod_list) = NULL;
	struct kmod_list *iter;
	int rc;

	ctx = kmod_new(NULL, NULL);
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
			rc = 1;
			return rc;
		case -ENOENT:
		case KMOD_MODULE_GOING:
			break;
		default:
			if (state < 0) {
				log(LOG_ERR,
				    "module \"%s\" initstate: %s\n",
				    real_name, strerror(-state));
				errno = -state;
			} else {
				log(LOG_ERR,
				    "module \"%s\" initstate %d unsupported\n",
				    real_name, state);
				errno = EINVAL;
			}
			rc = -1;
			break;
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
	struct kmod_ctx *ctx __cleanup__(cleanup_kmod_ctx) = NULL;
	struct kmod_list *lst __cleanup__(cleanup_kmod_list) = NULL;
	struct kmod_list *iter;
	int rc;

	ctx = kmod_new(NULL, NULL);
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
		else if (rc < 0) {
			log(LOG_ERR, "kmod_module_insert_module(%s): %s\n",
			    real_name, strerror(-rc));
			errno = -rc;
			return -1;
		} else {
			log(LOG_ERR,
			    "kmod_module_insert_module(%s): unexpected retcode %d\n",
			    real_name, rc);
			errno = -EINVAL;
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
	struct kmod_ctx *ctx __cleanup__(cleanup_kmod_ctx) = NULL;
	struct kmod_module *mod __cleanup__(cleanup_kmod_module) = NULL;
	int rc;
	uint64_t start_us;
	static const uint64_t LIMIT = 1000000;
	static const useconds_t SLEEP = LIMIT/10;

	ctx = kmod_new(NULL, NULL);
	if (!ctx)
		return -1;

	rc = kmod_module_new_from_name(ctx, name, &mod);
	if (rc == -ENOENT)
		return 0;
	else if (rc < 0) {
		log(LOG_ERR, "kmod_module_new_from_name: %s\n",
		    strerror(-rc));
		return -1;
	}

	start_us = now_us();
	for (;;) {
		rc = kmod_module_remove_module(mod, 0);
		if (rc == -ENOENT || rc == 0)
			return 0;
		else if (rc == -EAGAIN) {
			if (now_us() < start_us + LIMIT) {
				usleep(SLEEP);
				continue;
			}
		};
		if (rc < 0) {
			log(LOG_ERR, "remove \"%s\": %s",
			    kmod_module_get_name(mod),
			    strerror(-rc));
		}
		return -1;
	}
	return 0;
}
