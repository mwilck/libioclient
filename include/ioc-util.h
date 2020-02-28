#ifndef _IOC_UTIL_H
#define _IOC_UTIL_H

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
static pid_t __gettid(void)
{
	return syscall(SYS_gettid);
}
#define gettid __gettid
#endif

#define log(lvl, format, ...)						\
	do {								\
		if (lvl <= MAX_LOGLEVEL && lvl <= loglevel) {		\
		struct timespec __ts; pid_t __pid = gettid();		\
		clock_gettime(CLOCK_MONOTONIC, &__ts);			\
		fprintf(stderr, "[%ld.%06ld] (%d): " format,		\
			__ts.tv_sec, __ts.tv_nsec / 1000, __pid,	\
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

#endif
