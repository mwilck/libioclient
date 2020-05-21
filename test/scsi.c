#define _GNU_SOURCE 1
#include <sys/utsname.h>
#include <ioc-util.h>

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
