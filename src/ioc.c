#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/eventfd.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <libaio.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sched.h>
#include <syslog.h>
#include <poll.h>
#include <urcu/uatomic.h>
#include <urcu.h>
#include "ioc.h"
#include "ioc-internal.h"
#include "ioc-util.h"

// Copyright (c) 2020 Martin Wilck, SUSE Software Solutions GmbH

// SPDX-license-identifier: LGPL-2.0-or-later

/* Number of initially allocated IO requests */
#define N_REQUESTS 8
/* Number of events to pool for in io_getevents */
#define N_EVENTS 128
/* events that time out BLINK us in the future are considered timed out */
#define BLINK 0
/* a few extra us to be able to let io_pgetevents time out normally */
#define TIMER_EXTRA_US 100
/* time to sleep in io_getevents, us */
#define MAX_WAIT_US 10000000
/* signal to use to kill event thread */
#define SIG_EVSTOP SIGRTMIN
/* signal to use to tell event thread to re-init*/
#define SIG_EVUPDATE SIGRTMIN+1

/* LOG LEVEL, up to LOG_DEBUG + 1 */
#define DEFAULT_LOGLEVEL LOG_NOTICE

#define INVALID_SLOT ~0U

int __ioc_loglevel = (DEFAULT_LOGLEVEL > MAX_LOGLEVEL ?
		      MAX_LOGLEVEL : DEFAULT_LOGLEVEL);

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_key_t exit_key;

static void create_exit_key(void)
{
	(void)pthread_key_create(&exit_key, NULL);
}

const char *ioc_status_name(int st)
{
	unsigned int i;

	static const struct {
		int st_val;
		const char *const st_name;
	} ioc_status_names [] = {
		{ IOC_RUNNING, "running", },
		{ IOC_TIMEOUT, "timed out", },
		{ IOC_DONE, "done", },
		{ IOC_DONE|IOC_TIMEOUT, "done after timeout", },
		{ IOI_ERR, "error", },
		{ IOI_DISCARDED, "discarded", },
		{ IOI_DISCARDED|IOC_TIMEOUT, "discarded after timeout", },
		{ IOI_INVALID, "invalid", },
	};

	for (i = 0; i < sizeof(ioc_status_names)/sizeof(*ioc_status_names); i++) {
		if (st == ioc_status_names[i].st_val)
			return ioc_status_names[i].st_name;
	}
	return "UNKNOWN";
}

bool ioc_is_inflight(const struct iocb *iocb)
{
	return req_is_inflight(iocb2request_const(iocb));
}

bool ioc_has_timed_out(const struct iocb *iocb)
{
	return req_has_timed_out(iocb2request_const(iocb));
}

struct aio_group {
	io_context_t aio_ctx;
	unsigned int index;
	unsigned int nr_reqs;
	/* This lock protects access to the req member */
	pthread_rwlock_t req_lock;
	struct request **req;
	pthread_t event_thread;
	bool event_thread_running;
	/* Mutex/cond var for synchronization with event thread */
	pthread_mutex_t event_mutex;
	pthread_cond_t event_cond;
	timer_t event_timer;
	pthread_mutex_t timer_mutex;
	uint64_t timer_fires;
	struct context *ctx;
};

struct context {
	unsigned int refcount;
	unsigned int n_groups;
	pthread_rwlock_t group_lock;
	struct aio_group **group;
	bool unloading;
};

static inline struct context *context_from_group(struct aio_group *grp)
{
	return grp->ctx;
}

#ifndef SYS_io_pgetevents
static int __io_pgetevents(io_context_t ctx_id, long min_nr, long nr,
			 struct io_event *events, struct timespec *tmo,
			 sigset_t *sigmask)
{
	sigset_t old_mask;
	int rc;

	pthread_sigmask(SIG_SETMASK, sigmask, &old_mask);
	rc = io_getevents(ctx_id, min_nr, nr, events, tmo);
	pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	return rc;
}
#define io_pgetevents __io_pgetevents
#endif

static void mutex_unlock(void *arg)
{
	pthread_mutex_unlock((pthread_mutex_t*)arg);
}

static void rwlock_unlock(void *arg)
{
	pthread_rwlock_unlock((pthread_rwlock_t*) arg);
}

static void ref_context(struct context *c)
{
	int n = uatomic_add_return(&c->refcount, 1);
	log(LOG_DEBUG, "ctx +refcount=%d\n", n);
}

static void __destroy_aio_group(struct aio_group *grp)
{
	timer_delete(grp->event_timer);
	pthread_cond_destroy(&grp->event_cond);
	pthread_mutex_destroy(&grp->timer_mutex);
	pthread_mutex_destroy(&grp->event_mutex);
	pthread_rwlock_destroy(&grp->req_lock);
	free(grp->req);
	free(grp);
}

static void discard_aio_group(struct aio_group *grp);

static void __destroy_context(struct context *c)
{
	unsigned int i;

	/* FIXME: last ref has just been dropped, do we need locking? */
	pthread_rwlock_wrlock(&c->group_lock);
	pthread_cleanup_push(rwlock_unlock, &c->group_lock);
	for (i = c->n_groups; i; i--) {
		discard_aio_group(c->group[i - 1]);
		c->group[i - 1] = NULL;
	}
	pthread_cleanup_pop(1);
	pthread_rwlock_destroy(&c->group_lock);
	free(c->group);
	free(c);
}

static void unref_context(struct context *c)
{
	int n = uatomic_sub_return(&c->refcount, 1);

	if (n == 0)
		__destroy_context(c);
	log(LOG_DEBUG, "ctx -refcount=%d\n", n);
}

/* FIXME: make this lockless by calling it only from the event thread */
static void arm_event_timer(struct aio_group *grp, uint64_t time)
{
	struct itimerspec start_it = {
		.it_interval = { 0, },
	};

	if (time == 0)
		return;

	pthread_mutex_lock(&grp->timer_mutex);
	pthread_cleanup_push(mutex_unlock, &grp->timer_mutex);
	if (time < grp->timer_fires) {
		grp->timer_fires = time;
		us_to_ts(time, &start_it.it_value);
		if (timer_settime(grp->event_timer, TIMER_ABSTIME,
				   &start_it, NULL) != 0)
			log(LOG_WARNING, "failed to arm timer: %m\n");
		else
			log(LOG_DEBUG, "new expiry: %ld.%06ld\n",
			    start_it.it_value.tv_sec,
			    start_it.it_value.tv_nsec / 1000);
	}
	pthread_cleanup_pop(1);
}

static void disarm_event_timer(struct aio_group *grp)
{
	static const struct itimerspec stop_it = {
		.it_interval = { 0, },
		.it_value = { 0, },
	};

	pthread_mutex_lock(&grp->timer_mutex);
	pthread_cleanup_push(mutex_unlock, &grp->timer_mutex);
	if (grp->timer_fires < UINT64_MAX) {
		grp->timer_fires = UINT64_MAX;
		if (timer_settime(grp->event_timer, 0, &stop_it, NULL) != 0)
			log(LOG_WARNING, "failed to disarm timer: %m\n");
	} else
		log(LOG_DEBUG, "disarmed\n");
	pthread_cleanup_pop(1);
}

static void ref_request(struct request *r)
{
	int n;

	if (!r)
		return;
	 n = uatomic_add_return(&r->refcount, 1);
	 log(LOG_DEBUG + 1, "req %p +refcount=%u\n", r, n);
}

static void release_aio_slot(struct context *ctx, unsigned int n);

static void free_request(struct request *req)
{
	int status =  req_get_int_status(req);

	log(__ioc_is_inflight(status) ? LOG_ERR : LOG_DEBUG,
	    "freeing request %u, status %s\n",
	    req->idx, ioc_status_name(status));

	switch (req->notify_type) {
	case IOC_NOTIFY_COND:
		pthread_mutex_destroy(&req->notify.cv.mutex);
		pthread_cond_destroy(&req->notify.cv.cond);
		break;
	case IOC_NOTIFY_EVENTFD:
		close(req->notify.eventfd);
		break;
	default:
		break;
	}

	if (req->ctx && req->idx != INVALID_SLOT)
		release_aio_slot(req->ctx, req->idx);

	if (status & IOI_DISCARDED && req->free_resources) {
		log(LOG_INFO, "releasing resources\n");
		req->free_resources(&req->iocb);
	}
	free(req);
}

static void unref_request(struct request *r)
{
	unsigned int n;

	if (!r)
		return;
	n = uatomic_sub_return(&r->refcount, 1);
	if (n == 0)
		free_request(r);
	log(LOG_DEBUG + 1, "req %p -refcount=%u\n", r, n);
}

static void wakeup_waiters(struct aio_group *grp)
{
	pthread_cond_broadcast(&grp->event_cond);
}

/* Called with grp->req_lock held in write mode */
static void __unlink_request(struct aio_group *grp, unsigned int i)
{
	struct request *r;

	assert(i < N_REQUESTS);
	r = grp->req[i];
	if (!r)
		return;
	grp->req[i] = NULL;
	r->ctx = NULL;
	r->idx = INVALID_SLOT;
	uatomic_dec(&grp->nr_reqs);
}

static void unlink_request(struct aio_group *grp, unsigned int i)
{
	struct request *r;

	assert(i < N_REQUESTS);

	/* FIXME: do we need this wrlock? atomic, maybe? */
	pthread_rwlock_wrlock(&grp->req_lock);
	r = grp->req[i];
	grp->req[i] = NULL;
	r->ctx = NULL;
	r->idx = INVALID_SLOT;
	uatomic_dec(&grp->nr_reqs);
	pthread_rwlock_unlock(&grp->req_lock);
}

/* Called with grp->req_lock held in write mode */
static void __link_request(struct aio_group *grp, unsigned int i,
			   struct request *req)
{
	assert(i < N_REQUESTS);
	assert(grp->req[i] == NULL);

	grp->req[i] = req;
	req->idx = grp->index * N_REQUESTS * i;
	req->ctx = context_from_group(grp);
	uatomic_inc(&grp->nr_reqs);
}

static void link_request(struct aio_group *grp, unsigned int i,
			   struct request *req)
{
	struct request *old;

	assert(i < N_REQUESTS);

	pthread_rwlock_wrlock(&grp->req_lock);
	old = grp->req[i];
	grp->req[i] = req;
	req->idx = grp->index * N_REQUESTS * i;
	req->ctx = context_from_group(grp);
	pthread_rwlock_unlock(&grp->req_lock);

	assert(old == NULL);
	uatomic_inc(&grp->nr_reqs);
}

static void discard_aio_group(struct aio_group *grp)
{
	pthread_t et;
	int rc;

	pthread_mutex_lock(&grp->event_mutex);
	pthread_cleanup_push(mutex_unlock, &grp->event_mutex);
	if (grp->event_thread_running) {
		et = grp->event_thread;
		log(LOG_DEBUG, "cancel event thread %lu\n", et);
		rc = pthread_kill(et, SIG_EVSTOP);
		log(LOG_DEBUG, "pthread_kill -> %d\n", rc);
		rc = pthread_cancel(et);
		log(LOG_DEBUG, "pthread_cancel -> %d\n", rc);
		while (grp->event_thread_running)
			pthread_cond_wait(&grp->event_cond, &grp->event_mutex);
	}
	pthread_cleanup_pop(1);
	__destroy_aio_group(grp);
}

static int start_event_thread(struct aio_group *grp);

void ioc_put_context(struct context *c)
{
	uatomic_set(&c->unloading, true);
	unref_context(c);
}

static void event_timer_notify(union sigval arg)
{
	struct aio_group *grp = arg.sival_ptr;

	/* FIXME: WHY? */
	/* pthread_mutex_lock(&grp->timer_mutex);
	   ctx->timer_fires = UINT64_MAX;
	   pthread_mutex_unlock(&ctx->timer_mutex); */
	pthread_kill(grp->event_thread, SIG_EVUPDATE);
	log(LOG_DEBUG, "fired\n");
}

static int start_event_thread(struct aio_group *grp);

static int ioc_init_aio_group(struct aio_group *grp)
{
	struct sigevent se = {
		.sigev_notify = SIGEV_THREAD,
		.sigev_notify_function = event_timer_notify,
	};
	int rc;

	memset(grp, 0, sizeof(*grp));
	rc = io_setup(N_REQUESTS, &grp->aio_ctx); 
	if (rc < 0) {
		log(LOG_ERR, "io_setup: %s", strerror(-rc));
		goto out;
	}
	if (pthread_mutex_init(&grp->event_mutex, NULL))
		goto out_aio;

	if (pthread_cond_init(&grp->event_cond, NULL))
		goto out_mutex;

	if (pthread_rwlock_init(&grp->req_lock, NULL))
		goto out_cond;

	se.sigev_value.sival_ptr = grp;
	if (timer_create(CLOCK_MONOTONIC, &se, &grp->event_timer) != 0) {
		log(LOG_ERR, "timer_create: %m\n");
		goto out_rwlock;
	}

	if (pthread_mutex_init(&grp->timer_mutex, NULL))
		goto out_timer;

	grp->req = calloc(N_REQUESTS, sizeof(*grp->req));
	if (grp->req == NULL)
		goto out_timer_mutex;

	grp->nr_reqs = 0;
	disarm_event_timer(grp);

	return 0;

out_aio:
	io_destroy(grp->aio_ctx);
out_timer_mutex:
	pthread_mutex_destroy(&grp->timer_mutex);
out_timer:
	timer_delete(grp->event_timer);
out_rwlock:
	pthread_rwlock_destroy(&grp->req_lock);
out_cond:
	pthread_cond_destroy(&grp->event_cond);
out_mutex:
	pthread_mutex_destroy(&grp->event_mutex);
out:
	return -1;
}

static int __add_aio_group(struct context *c, struct aio_group *new_grp)
{
	struct aio_group **tmp;
	unsigned int wanted = c->n_groups + 1;

	tmp = realloc(c->group, wanted * sizeof(*c->group));
	if (tmp != NULL) {
		c->group = tmp;
		new_grp->index = c->n_groups;
		new_grp->ctx = c;
		if (start_event_thread(new_grp) == 0) {
			c->group[c->n_groups] = new_grp;
			log(LOG_DEBUG, "added new aio_group %u\n",
			    c->n_groups);
			c->n_groups++;
			return 0;
		}
	}
	log(LOG_ERR, "failed to add group %u\n",
	    c->n_groups);
	return -1;
}

static  struct aio_group *add_aio_grp(struct context *c)
{
	struct aio_group *grp = calloc(1, sizeof(*grp));

	if (!grp)
		return NULL;

	if (ioc_init_aio_group(grp) == 0 && __add_aio_group(c, grp) == 0)
		return grp;
	else {
		free(grp);
		return NULL;
	}
}

struct context *ioc_create_context(void)
{
	struct context *c;

	c = calloc(1, sizeof(struct context));
	if (c == NULL)
		return c;

	if (pthread_rwlock_init(&c->group_lock, NULL))
		goto out_free;

	c->n_groups = 0;

	ref_context(c);
	return c;

out_free:
	free(c);
	return NULL;
}

static unsigned int group_index(unsigned int n, unsigned int *req_idx)
{
	unsigned int ng = n / N_REQUESTS;
	unsigned int nr = n % N_REQUESTS;

	*req_idx = nr;
	return ng;
}

static void release_aio_slot(struct context *ctx, unsigned int n)
{
	struct aio_group *grp = NULL;
	unsigned int group_idx, req_idx;

	group_idx = group_index(n, &req_idx);
	pthread_rwlock_rdlock(&ctx->group_lock);
	if (group_idx < ctx->n_groups)
		grp = ctx->group[group_idx];
	pthread_rwlock_unlock(&ctx->group_lock);

	if (grp == NULL) {
		log(LOG_ERR, "request to unref invalid entry %u\n", n);
		return;
	}

	unlink_request(ctx->group[group_idx], req_idx);

	log(LOG_DEBUG, "released %u\n", n);
	unref_context(ctx);
}

static unsigned int __find_aio_slot_in_group(struct aio_group *grp)
{
	unsigned int i;

	for (i = 0; i < N_REQUESTS; i++)
		if (!grp->req[i])
			return i;
	return N_REQUESTS;
}

static unsigned int try_to_alloc_slot_in_group(struct aio_group *grp,
					       struct request *req)
{
	unsigned int idx;

	pthread_rwlock_wrlock(&grp->req_lock);
	pthread_cleanup_push(rwlock_unlock, &grp->req_lock);
	if (uatomic_read(&grp->nr_reqs) < N_REQUESTS) {
		idx = __find_aio_slot_in_group(grp);
		if (idx < N_REQUESTS)
			__link_request(grp, idx, req);
	} else
		idx = N_REQUESTS;
	pthread_cleanup_pop(1);
	return idx;
}

static unsigned int alloc_aio_slot(struct context *c, struct request *req)
{
	unsigned int i, n = INVALID_SLOT;

	assert(req != NULL);

	ref_context(c);
	pthread_rwlock_rdlock(&c->group_lock);
	pthread_cleanup_push(rwlock_unlock, &c->group_lock);
	for (i = 0; i < c->n_groups; i++) {
		struct aio_group *grp = c->group[i];
		unsigned int idx;

		if (uatomic_read(&grp->nr_reqs) >= N_REQUESTS)
			continue;

		idx = try_to_alloc_slot_in_group(grp, req);
		if (idx < N_REQUESTS) {
			n = i * N_REQUESTS + idx;
			break;
		}
	}
	pthread_cleanup_pop(1);
	if (n != INVALID_SLOT) {
		log(LOG_DEBUG, "slot %u allocated\n", n);
		return n;
	}

	pthread_rwlock_wrlock(&c->group_lock);
	pthread_cleanup_push(rwlock_unlock, &c->group_lock);
	/* i was c->nr_groups before we released and re-acquired the lock */
	if (i < c->n_groups) {
		struct aio_group *grp = c->group[i];
		unsigned int idx;

		if (uatomic_read(&grp->nr_reqs) < N_REQUESTS) {
			idx = try_to_alloc_slot_in_group(grp, req);
			if (idx < N_REQUESTS)
				n = i * N_REQUESTS + idx;
		}
	}
	if (n == INVALID_SLOT) {
		struct aio_group *grp = add_aio_grp(c);

		if (grp) {
			link_request(grp, 0, req);
			n = grp->index * N_REQUESTS;
		}
	}
	pthread_cleanup_pop(1);
	if (n == INVALID_SLOT) {
		log(LOG_ERR, "failed to allocate slot\n");
		unref_context(c);
	} else
		log(LOG_DEBUG, "slot %u allocated\n", n);
	return n;
}

int ioc_submit(struct iocb *iocb, uint64_t deadline)
{
	struct request *req;
	struct context *ctx;
	unsigned int group_idx, req_idx;
	int rc, ret;

	if (!iocb) {
		errno = EINVAL;
		return -1;
	}

	req = iocb2request(iocb);
	if (__ioc_is_inflight(req_get_int_status(req))) {
		errno = EBUSY;
		return -1;
	}
	ctx = req->ctx;
	if (ctx == NULL || uatomic_read(&ctx->unloading)) {
		log(LOG_ERR, "attempt to submit to unloading context\n");
		errno = ESHUTDOWN;
		return -1;
	}
	group_idx = group_index(req->idx, &req_idx);

	if (deadline) {
		struct timespec now_ts;
		uint64_t now;

		clock_gettime(CLOCK_MONOTONIC, &now_ts);
		now = ts_to_us(&now_ts);
		req->deadline = UINT64_MAX - deadline > now ?
			now + deadline : UINT64_MAX;
	} else
		req->deadline = UINT64_MAX;

	/* pthread_rwlock_rdlock(&ctx->ctx_lock);
	   pthread_cleanup_push(rwlock_unlock, &ctx->ctx_lock); */

	rc = io_submit(ctx->group[group_idx]->aio_ctx, 1, &iocb);

	if (rc != 1) {
		uatomic_set(&req->io_status, IOI_ERR);
		log(LOG_ERR, "io_submit (%u): %s\n", group_idx, strerror(-rc));
		ret = -1;
		errno = -rc;
	} else {
		/* This ref is held by "the kernel" and dropped when the IO completes */
		ref_request(req);
		uatomic_set(&req->io_status, IOC_RUNNING);
		arm_event_timer(ctx->group[group_idx], req->deadline);
		if (deadline)
			log(LOG_DEBUG, "req %u timeout %" PRIu64 "us -> %" PRIu64 "\n",
			    req->idx, deadline, req->deadline);
		else
			log(LOG_DEBUG, "req %u no timeout\n", req->idx);
		ret = 0;
	}

	return ret;
}

int ioc_get_status(const struct iocb *iocb)
{
	const struct request *req;

	if (!iocb)
		return IOI_INVALID;

	req = iocb2request_const(iocb);
	return req_get_int_status(req) & IOI_PUBLIC_MASK;
}

static void eat_pending_events(int fd)
{
	int rc;
	struct pollfd pf = {
		.fd = fd,
		.events = POLLIN,
	};
	uint64_t val;

	while ((rc = poll(&pf, 1, 0)) > 0) {
		rc = read(fd, &val, 8);
		log(LOG_DEBUG,
		    "(%d) read %" PRIu64 " from fd=%d\n", rc,
		    rc > 0 ? val : (uint64_t)0, fd);
	}
}

static inline int ioc_wait_for_cond(unsigned int mask, struct request *req,
				    pthread_cond_t *cond,
				    pthread_mutex_t *mutex)
{
	int _rv;

	pthread_mutex_lock(mutex);
	pthread_cleanup_push(mutex_unlock, mutex);
	while (((_rv = req_get_int_status(req)) & mask) == 0)
		pthread_cond_wait(cond, mutex);
	pthread_cleanup_pop(1);
	return _rv;
}


static int _ioc_wait(struct iocb *iocb, unsigned int mask)
{
	struct request *req;
	uint64_t val;
	int rc = 0, rv = 0;
	unsigned int ig, ir;
	struct aio_group *grp;

	if (!iocb) {
		errno = EINVAL;
		return -1;
	}

	req = iocb2request(iocb);
	log(LOG_DEBUG, "type = %d val=%d mask=%08x\n",
	    req->notify_type, req_get_int_status(req), mask);

	/* Caller must hold a ref to the request. It is illegal to wait
	   after calling ioc_put_iocb() */
	switch (req->notify_type) {
	case IOC_NOTIFY_COMMON:
		ig = group_index(req->idx, &ir);
		grp = req->ctx->group[ig];
		rv = ioc_wait_for_cond(mask, req,
				       &grp->event_cond,
				       &grp->event_mutex);
		break;
	case IOC_NOTIFY_COND:
		rv = ioc_wait_for_cond(mask, req,
				       &req->notify.cv.cond,
				       &req->notify.cv.mutex);
		break;
	case IOC_NOTIFY_EVENTFD:
		eat_pending_events(req->notify.eventfd);
		while (((rv = req_get_int_status(req)) & mask) == 0) {
			struct pollfd pf = {
				.fd = req->notify.eventfd,
				.events = POLLIN,
			};

			do {
				rc = poll(&pf, 1, -1);
			} while (rc == -1 && errno == EAGAIN);

			if (rc == -1) {
				log(LOG_ERR, "poll: %m\n");
				break;
			}
			log(LOG_DEBUG + 1, "sts=%x=%s\n", rv,
			    ioc_status_name(rv));
			rc = read(req->notify.eventfd, &val, 8);
			log(LOG_DEBUG,
			    "(%d) read %"PRIu64" from fd=%d\n",
			    rc, rc > 0 ? val : (uint64_t)0,
			    req->notify.eventfd);
			if (rc > 0) {
				rc = 0;
			} else {
				log(LOG_ERR, "read: %m\n");
				break;
			}
		}
		break;
	default:
		errno = -EINVAL;
		return -1;
	}

	log(LOG_DEBUG, "rc=%d rv=%d\n", rc, rv);
	if (rc != 0)
		log(LOG_ERR, "error: %m\n");
	return rc;
}

int ioc_wait_done(struct iocb *iocb) {
	return _ioc_wait(iocb, ~IOC_TIMEOUT);
}

int ioc_wait_event(struct iocb *iocb) {
	return _ioc_wait(iocb, ~0);
}

int ioc_get_eventfd(const struct iocb *iocb) {
	const struct request *req;

	if (iocb == NULL) {
		errno = EINVAL;
		return -1;
	}
	req = iocb2request_const(iocb);
	if (req->notify_type != IOC_NOTIFY_EVENTFD) {
		errno = EINVAL;
		return -1;
	}
	return req->notify.eventfd;
}

void ioc_put_iocb(struct iocb *iocb)
{
	struct request *req;

	if (!iocb)
		return;
	req = iocb2request(iocb);

	/* avoid further notifcations to be sent */
	uatomic_add_return(&req->io_status, IOI_DISCARDED);
	unref_request(req);
}

void ioc_put_iocb_cleanup(void *arg)
	__attribute__((weak, alias("ioc_put_iocb")));

static int ioc_set_notify(struct iocb *iocb, unsigned int type)
{
	struct request *req;
	int rv;

	if (!iocb || type > IOC_NOTIFY_NONE) {
		errno = EINVAL;
		return -1;
	}
	req = iocb2request(iocb);
	switch (type) {
	case IOC_NOTIFY_COND:
		rv = pthread_cond_init(&req->notify.cv.cond, NULL);
		if (rv != 0) {
			log(LOG_ERR,
			    "error initializing condition variable");
			errno = rv;
			return -1;
		}
		rv = pthread_mutex_init(&req->notify.cv.mutex, NULL);
		if (rv != 0) {
			log(LOG_ERR,
			    "error initializing mutex");
			pthread_cond_destroy(&req->notify.cv.cond);
			errno = rv;
			return -1;
		}
		break;
	case IOC_NOTIFY_EVENTFD:
		req->notify.eventfd = eventfd(0, 0);
		if (req->notify.eventfd == -1) {
			log(LOG_ERR, "eventfd: %m\n");
			return -1;
		}
		log(LOG_DEBUG, "job %d fd=%d\n",
		    req->idx, req->notify.eventfd);
		break;
	case IOC_NOTIFY_NONE:
	case IOC_NOTIFY_COMMON:
		break;
	default:
		log(LOG_ERR, "invalid notification type: %u\n",
		    type);
		errno = EINVAL;
		return -1;
	}
	req->notify_type = type;
	return 0;
}

struct iocb *ioc_new_iocb(struct context *ctx, enum ioc_notify_type type,
			  void (*free_resources)(struct iocb*))
{
	struct request *req;
	unsigned int n;

	if (!ctx || uatomic_read(&ctx->unloading)) {
		log(LOG_ERR, "called on unloading context\n");
		errno = ESHUTDOWN;
		return NULL;
	}
	req = calloc(1, sizeof(*req));
	if (!req)
		return NULL;

	ref_request(req);
	uatomic_set(&req->io_status, IOC_DONE);

	if (ioc_set_notify(&req->iocb, type) != 0) {
		unref_request(req);
		return NULL;
	}
	/* alloc_aio_slot() increases refcount */
	n = alloc_aio_slot(ctx, req);
	if (n == INVALID_SLOT) {
		log(LOG_ERR, "failed to allocate slot\n");
		errno = ERANGE;
		free(req);
		return NULL;
	}
	req->ctx = ctx;
	req->idx = n;
	req->free_resources = free_resources;
	return &req->iocb;
}

static bool event_notify(struct request *req)
{
	static uint64_t val = 1;

	switch (req->notify_type) {
	case IOC_NOTIFY_EVENTFD:
		write(req->notify.eventfd, &val, sizeof(val));
		log(LOG_DEBUG, "wrote %"PRIu64" to fd=%d\n",
		    val, req->notify.eventfd);
		val++;
		break;
	case IOC_NOTIFY_COND:
		pthread_cond_broadcast(&req->notify.cv.cond);
		break;
	case IOC_NOTIFY_COMMON:
		/* common will be woken up later */
		return true;
	default:
		break;
	};
	return false;
}

static bool handle_completions(int n, const struct io_event *events)
{
	int i;
	bool action_needed = false;

	for (i = 0; i < n; i++) {
		struct request *req;
		int status;

		req = iocb2request(events[i].obj);
		status = uatomic_add_return(&req->io_status, IOC_DONE);

		log(LOG_DEBUG,
		    "req %u compl: st=%s %ld %lu ofs=%lld\n",
		    req->idx, ioc_status_name(status),
		    events[i].res, events[i].res2,
		    events[i].obj->u.c.offset);

		if (!(status & IOI_DISCARDED))
			action_needed = action_needed || event_notify(req);

		unref_request(req);
	}

	return action_needed;
}

static void event_thread_cleanup(void *arg)
{
	struct aio_group *grp = arg;
	io_context_t trash_ctx;
	unsigned int i, n_inflight;

	/* we are already cancelled */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	disarm_event_timer(grp);

	pthread_rwlock_wrlock(&grp->req_lock);
	for (i = 0, n_inflight = 0; i < N_REQUESTS; i++) {
		struct request *req = grp->req[i];
		struct io_event ev;

		if (!req)
			continue;

		if (req_is_inflight(req)) {
			/* This fails always, try nonetheless */
			io_cancel(grp->aio_ctx, &req->iocb, &ev);
			/* drop "in-flight" ref
			   - requests may be freed, buffers are not */
			unref_request(grp->req[i]);
			n_inflight++;
		}
		__unlink_request(grp, i);
	}
	pthread_rwlock_unlock(&grp->req_lock);

	trash_ctx = grp->aio_ctx;
	grp->aio_ctx = 0;

	/* Tell them we're leaving */
	pthread_mutex_lock(&grp->event_mutex);
	grp->event_thread_running = false;
	pthread_cond_broadcast(&grp->event_cond);
	pthread_mutex_unlock(&grp->event_mutex);

	log(LOG_NOTICE, "detaching with %u requests in flight\n",
	    n_inflight);

	pthread_detach(pthread_self());
	/* This may block */
	io_destroy(trash_ctx);
}

static void event_stop_handler(int sig __attribute__((unused)))
{
	bool *pex = pthread_getspecific(exit_key);
	if (pex)
		uatomic_set(pex, true);
};

static void event_upd_handler(int sig __attribute__((unused)))
{
	/* empty */
};

static bool event_thread_action(struct aio_group *grp, sigset_t *mask,
				bool *_exit)
{
	struct io_event events[N_EVENTS];
	struct timespec ts;
	uint64_t now, max_wait;
	unsigned int i;
	int rc;
	bool action_needed = false;
	bool must_quit = false;
	struct request *req;

	while (pthread_rwlock_tryrdlock(&grp->req_lock) != 0) {
		pthread_testcancel();
		sched_yield();
	}
	pthread_cleanup_push(rwlock_unlock, &grp->req_lock);

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts_to_us(&ts);
	max_wait = UINT64_MAX - MAX_WAIT_US > now ?
		now + MAX_WAIT_US : UINT64_MAX;

	for (i = 0; i < N_REQUESTS; i++) {
		req = grp->req[i];
		if (!req)
			continue;
		if (req->deadline < now + BLINK) {
			if (uatomic_cmpxchg(&req->io_status,
					    IOC_RUNNING, IOC_TIMEOUT)
			    == IOC_RUNNING) {
				action_needed = action_needed ||
					event_notify(req);
				log(LOG_DEBUG,
				    "req %u: timed out, sts=%s\n", req->idx,
				    ioc_status_name(req_get_int_status(req)));
			}
		} else if (req->deadline < max_wait && req_is_inflight(req))
			max_wait = req->deadline;
	}
	pthread_cleanup_pop(1);

	if (action_needed) {
		wakeup_waiters(grp);
		log(LOG_DEBUG, "tmo: %" PRIu64 "\n", now);
	}

	arm_event_timer(grp, max_wait + TIMER_EXTRA_US);

	max_wait -= now;
	us_to_ts(max_wait, &ts);

	log(LOG_DEBUG, "timeout = %" PRIu64 "us\n", max_wait);

	pthread_testcancel();

	/* If io_pgetevents returns anything, we need to act on it */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	rc = io_pgetevents(grp->aio_ctx, 1, N_EVENTS, events, &ts, mask);

	if (rc == -EINTR) {
		if (uatomic_read(_exit)) {
			log(LOG_NOTICE, "exit signal received\n");
			must_quit = true;
		} else {
			log(LOG_DEBUG, "update signal received\n");
		}
	} else if (rc < 0) {
		log(LOG_ERR, "io_pgetevents: retcode = %d\n", rc);
		must_quit = true;
	}

	if (rc > 0 && handle_completions(rc, events))
		wakeup_waiters(grp);

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_testcancel();

	return must_quit;
}

static void *event_thread(void *arg)
{
	struct aio_group *grp = arg;
	sigset_t mask;
	bool _exit = false;
	static const struct sigaction stop_sa =
		{ .sa_handler = event_stop_handler, };
	static const struct sigaction upd_sa =
		{ .sa_handler = event_upd_handler, };

	sigfillset(&mask);
	if (pthread_sigmask(SIG_SETMASK, &mask, NULL) != 0) {
		log(LOG_ERR, "pthread_sigmask: %m\n");
		return NULL;
	}

	pthread_setspecific(exit_key, &_exit);
	if (sigaction(SIG_EVSTOP, &stop_sa, NULL) != 0) {
		log(LOG_ERR, "sigaction STOP: %m\n");
		return NULL;
	}
	if (sigaction(SIG_EVUPDATE, &upd_sa, NULL) != 0)
		log(LOG_ERR, "sigaction UPDATE: %m\n");

	sigdelset(&mask, SIG_EVSTOP);
	sigdelset(&mask, SIG_EVUPDATE);

	ref_context(context_from_group(grp));
	pthread_cleanup_push(event_thread_cleanup, grp);

	pthread_mutex_lock(&grp->event_mutex);
	grp->event_thread = pthread_self();
	grp->event_thread_running = true;
	pthread_cond_broadcast(&grp->event_cond);
	pthread_mutex_unlock(&grp->event_mutex);

	log(LOG_INFO, "starting\n");

	while (!event_thread_action(grp, &mask, &_exit));

	pthread_cleanup_pop(1);
	return NULL;
}

static int start_event_thread(struct aio_group *grp)
{
	pthread_t pt;
	int rc;

	pthread_mutex_lock(&grp->event_mutex);
	pthread_cleanup_push(mutex_unlock, &grp->event_mutex);

	rc = pthread_create(&pt, NULL, event_thread, grp);
	if (rc == 0) {
		while (!grp->event_thread_running)
			pthread_cond_wait(&grp->event_cond, &grp->event_mutex);
	}
	pthread_cleanup_pop(1);

	if (rc == 0)
		log(LOG_DEBUG, "created event thread %ld\n", pt);
	else
		log(LOG_ERR, "pthread_create: %m");
	return rc;
}

static void set_loglevel(void)
{
	static const char env_loglvl[] = "LIBIOC_LOGLEVEL";
	const char *lvl;
	char *end;
	long n;

	lvl = getenv(env_loglvl);
	if (!lvl || !*lvl)
		return;

	n = strtol(lvl, &end, 10);
	if (*end || n < LOG_EMERG || n > MAX_LOGLEVEL) {
		log(LOG_ERR, "Invalid value for %s: %s\n",
		    env_loglvl, lvl);
		return;
	}
	__ioc_loglevel = n;
}

int libioc_init(void)
{
	(void)pthread_once(&init_once, create_exit_key);
	set_loglevel();
	return 0;
}
