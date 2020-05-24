#define _GNU_SOURCE 1
#include <sys/utsname.h>
#include <ioc-util.h>

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

#define __cleanup__(f) __attribute__((cleanup(f)))

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

	kmod_list_foreach(iter, lst) {
		struct kmod_module *mod
			__cleanup__(cleanup_kmod_module) = NULL;
		int state;

		mod = kmod_module_get_module(iter);
		if (mod) {
			state = kmod_module_get_initstate(mod);
			if (state == -ENOENT) {
				rc = 0;
				break;
			} else if (state < 0) {
				log(LOG_ERR, "module \"%s\" initstate: %s\n",
				    kmod_module_get_name(mod),
				    strerror(-state));
				rc = -1;
				break;
			} else {
				log(LOG_DEBUG, "module \"%s\" initstate: %d\n",
				    kmod_module_get_name(mod), state);
				rc = 1;
			}
		}
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

	kmod_list_foreach(iter, lst) {
		struct kmod_module *mod
			__cleanup__(cleanup_kmod_module) = NULL;

		mod = kmod_module_get_module(iter);
		if (!mod)
			continue;
		rc = kmod_module_insert_module(mod, 0, NULL);
		if (rc == -EEXIST)
			rc = 0;
		if (rc < 0) {
			log(LOG_ERR, "kmod_module_insert_module %s: %s\n",
			    kmod_module_get_name(mod),
			    strerror(-rc));
			break;
		}
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
