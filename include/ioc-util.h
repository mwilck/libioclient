#ifndef _IOC_UTIL_H
#define _IOC_UTIL_H
#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#if (__GLIBC__ == 2 && __GLIBC_MINOR__ < 30) || __USE_GNU != 1
#include <syscall.h>
static pid_t __gettid(void)
{
	return syscall(SYS_gettid);
}
#define gettid() __gettid()
#endif

#define IOC_LOG_TIME_FMT "[%ld.%06ld] (%d/%s): "

extern int __ioc_loglevel;
#define log(lvl, format, ...)						\
	do {								\
		int __lvl = (lvl);					\
		if (__lvl <= MAX_LOGLEVEL && __lvl <= __ioc_loglevel) {	\
		struct timespec __ts; pid_t __pid = gettid();		\
		clock_gettime(CLOCK_MONOTONIC, &__ts);			\
		fprintf(stderr, IOC_LOG_TIME_FMT format,		\
			__ts.tv_sec, __ts.tv_nsec / 1000, __pid, __func__, \
			##__VA_ARGS__);					\
	}								\
	} while (0)

static inline uint64_t ts_to_us(const struct timespec *ts)
{
	return ts->tv_sec * 1000000ULL + ts->tv_nsec / 1000;
}

static inline void us_to_ts(uint64_t us, struct timespec *ts)
{
	ts->tv_sec = us / 1000000;
	ts->tv_nsec = (us % 1000000) * 1000;
}

static inline uint64_t now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts_to_us(&ts);
}

#define __cleanup__(f) __attribute__((cleanup(f)))

static inline void cleanup_fclose(FILE **f)
{
	if (f && *f)
		fclose(*f);
}

static inline void cleanup_free_charp(char **p)
{
	if (p)
		free(*p);
}

static inline void cleanup_free_voidp(void **p)
{
	if (p)
		free(*p);
}

#endif
