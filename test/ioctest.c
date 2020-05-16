#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/eventfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <libaio.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>
#include <ioc.h>
#include <ioc-util.h>
// #include <mcheck.h>

// Copyright (c) 2020 Martin Wilck, SUSE Software Solutions GmbH

// SPDX-license-identifier: GPL-2.0-or-later

/* Number of concurrent IO threads */
#define N_THREADS 32
/* IO timeout until a job is considered timed out */
#define JOB_TIMEOUT_US 20000
/* Runtime: Time to run random start / stop of IO threads */
#define RUNTIME_US 10000000
/* wait time between starting IO jobs */
#define WAIT_RAMPUP_US 100000
/* time to wait between randomly stopping / starting IO jobs */
#define MAX_WAIT_RAND_US 100000
/* Max sleep time between sending IO jobs from IO thread */
#define MAX_SLEEP_US 1000
/* IO size to use */
#define IOSIZE 1024*1024
/* IO buffer alignment */
#define ALIGN 4096

/* LOG LEVEL, up to LOG_DEBUG + 1 */
#define LOGLEVEL LOG_NOTICE

/* Notification method to use, see below */
/* use per-thread eventfd */
#define IOC_NOTIFY IOC_NOTIFY_EVENTFD
/* use per-thread cond variable */
// #define IOC_NOTIFY IOC_NOTIFY_COND
/* use shared cond variable */
//#define IOC_NOTIFY IOC_NOTIFY_COMMON

struct io_job {
	struct context *ctx;
	int fd;
	unsigned int n;
	uint64_t tmo;
};

struct stats
{
	unsigned long requests, completed, timedout, bytes,
		bad;
	long overtime, maxdelta;
	struct io_job *job;
};

static void print_stats(void *arg)
{
	struct stats *s = arg;

	log(LOG_NOTICE, "job %u requests: %lu, good: %lu (%luMiB), timeout: %lu, bad: %lu, avg delta %ld, max delta %ld\n",
	    s->job->n,
	    s->requests, s->completed,
	    s->bytes/1024/1024, s->timedout, s->bad,
	    s->overtime / ((long)s->timedout + 1), s->maxdelta);
}

static void *io_thread(void *arg)
{
	struct io_job *job = arg;
	off_t size, ofs, max_pg;
	struct stat st;
	char *buf = NULL;
	struct context *ctx = job->ctx;
	struct iocb *iocb;
	struct stats stats;

	memset(&stats, 0, sizeof(stats));
	stats.job = job;

	pthread_cleanup_push(free, job);
	pthread_cleanup_push(print_stats, &stats);

	if (fstat(job->fd, &st) != 0) {
		log(LOG_ERR, "fstat: %m");
		return NULL;
	}

	size = st.st_size;
	if (size == 0 && S_ISBLK(st.st_mode)) {
		uint64_t arg;
		int rc = ioctl(job->fd, BLKGETSIZE64, &arg);

		if (rc < 0 || arg <= 0) {
			log(LOG_ERR, "unable to determine size: %m\n");
			return NULL;
		} else
			size = arg;
	}

	if (IOSIZE >= size) {
		log(LOG_ERR, "devices size %ld blocks is too small\n", size);
		return NULL;
	}

	max_pg = (size - IOSIZE) / ALIGN;

	if (posix_memalign((void**)&buf, ALIGN, IOSIZE) != 0) {
		log(LOG_ERR, "posix_memalign: %m\n");
		return NULL;
	}
	pthread_cleanup_push(free, buf);

	iocb = ioc_new_iocb(ctx, IOC_NOTIFY, NULL);
	if (!iocb) {
		free(buf);
		log(LOG_ERR, "ioc_new_iocb: %m\n");
		return NULL;
	}
	pthread_cleanup_push(ioc_put_iocb_cleanup, iocb);

	log(LOG_DEBUG, "io thread %d starting, size %ld\n", job->n, size);

	for (;;) {

		int rc = -1;
		int r, sts;
		uint64_t tmo, tmo_abs;

		if (ioc_wait_done(iocb, NULL) == -1) {
			log(LOG_ERR, "failed to wait for idle: %m\n");
			break;
		}
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		pthread_testcancel();

		ofs = ((uint64_t)rand() % max_pg) * ALIGN;
		io_prep_pread(iocb, job->fd, buf, IOSIZE, ofs);

	repeat:
		if (ioc_reset(iocb) == -1) {
			log(LOG_ERR, "ioc_reset: %m\n");
			break;
		}

		/* We can't free our data structures as long as I/O
		   is in flight */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		for (;;) {
			struct timespec ts;

			tmo = job->tmo + (rand() % job->tmo) / 2;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			rc = ioc_submit(iocb, tmo);
			tmo_abs = ts_to_us(&ts) + tmo;

			if (rc == 0) {
				stats.requests++;
				break;
			}
			sched_yield();
		}

		r = ioc_wait_event(iocb, &sts);
		if (r == -1) {
			log(LOG_ERR, "failed to wait for completion: %m\n");
			break;
		}

		log(LOG_INFO, "job %d sts=%s\n", job->n, ioc_status_name(sts));

		if (__ioc_is_inflight(sts)) {
			int64_t delta;
			struct timespec ts_now;

			clock_gettime(CLOCK_MONOTONIC, &ts_now);
			delta = ts_to_us(&ts_now) - tmo_abs;
			stats.timedout++;
			stats.overtime += delta;
			if (delta > stats.maxdelta)
				stats.maxdelta = delta;
			if (delta < 0) {
				log(LOG_NOTICE, "%s, now %" PRIu64 ", deadline %" PRIu64 ", delta=%" PRId64 "\n",
				    ioc_status_name(sts), ts_to_us(&ts_now),
				    tmo, delta);
			}
		} else if (sts == IO_DONE) {
			stats.completed++;
			stats.bytes += IOSIZE;
		} else {
			stats.bad++;
			sched_yield();
			goto repeat;
		}

		usleep(rand() % MAX_SLEEP_US);
	}

	log(LOG_NOTICE, "io thread %d exiting:\n", job->n);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return NULL;
}

static pthread_t start_thread(struct context *ctx, int fd, int n)
{
	struct io_job *job = calloc(1, sizeof(*job));
	pthread_t pt;

	if (!job)
		return 0;
	job->ctx = ctx;
	job->fd = fd;
	job->n = n;
	job->tmo = JOB_TIMEOUT_US;

	if (pthread_create(&pt, NULL, io_thread, job) != 0) {
		log(LOG_ERR, "pthread_create: %m\n");
		return 0;
	}
	log(LOG_DEBUG, "created thread %d\n", n);
	return pt;
}

int main(int argc, const char *const argv[])
{
	struct context *ctx;
	int fd, i, rc = 1;
	pthread_t threads[N_THREADS];
	uint64_t stop;
	struct timespec ts;

	// mtrace();
	libioc_init();

	if (argc != 2) {
		log(LOG_ERR, "filename argument missing\n");
		return 1;
	}

	ctx = ioc_create_context();
	if (ctx == NULL)
		return rc;

	fd = open(argv[1], O_RDONLY|O_DIRECT);
	if (fd == -1) {
		log(LOG_ERR, "error opening %s: %m\n", argv[1]);
		goto out_destroy;
	}

	log(LOG_NOTICE, "startup\n");
	for(i = 0; i < N_THREADS; i++) {
		threads[i] = start_thread(ctx, fd, i);
		usleep(WAIT_RAMPUP_US);
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);
	stop = ts_to_us(&ts) + RUNTIME_US;

	log(LOG_NOTICE, "random walk\n");
	for(;;) {

		for (i = 0; i < N_THREADS; i++) {
			usleep(rand() % MAX_WAIT_RAND_US);
			if (rand() % 3 < 2)
				continue;
			if (pthread_equal(threads[i], 0)) {
				log(LOG_INFO,
				    "random start io thread %d\n", i);
				threads[i] = start_thread(ctx, fd, i);
			} else {
				void *res;

				log(LOG_INFO,
				    "random cancel io thread %d\n", i);
				pthread_cancel(threads[i]);
				pthread_join(threads[i], &res);
				threads[i] = 0;
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ts_to_us(&ts) >= stop)
			break;
	}

	log(LOG_NOTICE, "shutdown\n");
	for(i = 0; i < N_THREADS; i++) {
		if (!pthread_equal(threads[i], 0)) {
			log(LOG_INFO, "cancel io thread %d\n", i);
			pthread_cancel(threads[i]);
		}
	}

	for(i = 0; i < N_THREADS; i++) {
		if (!pthread_equal(threads[i], 0)) {
			void *res;
			log(LOG_DEBUG, "join io thread %d\n", i);
			pthread_join(threads[i], &res);
		}
	}

	close(fd);
	rc = 0;
out_destroy:
	ioc_destroy_context(ctx);
	log(LOG_NOTICE, "done\n");
	//  muntrace();
	return rc;
}
