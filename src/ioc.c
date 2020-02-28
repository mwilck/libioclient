#define _GNU_SOURCE 1
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

#define container_of(ptr, type, member) ({		\
			typeof( ((type *)0)->member ) *__mptr = (ptr);	\
			(type *)( (char *)__mptr - offsetof(type,member) );})
#define container_of_const(ptr, type, member) ({		\
			typeof( ((const type *)0)->member ) *__mptr = (ptr); \
			(const type *)( (const char *)__mptr - \
					offsetof(type,member) );})

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_key_t exit_key;

static void create_exit_key(void)
{
	(void)pthread_key_create(&exit_key, NULL);
}

static struct {
	int st_val;
	char *st_name;
} _status_names [] = {
	{ IO_RUNNING, "running", },
	{ IO_TIMEOUT, "timed out", },
	{ IO_DONE, "done", },
	{ IO_DONE|IO_TIMEOUT, "done after timeout", },
	{ IO_ERR, "error", },
	{ IO_ERR|IO_TIMEOUT, "error after timeout", },
	{ IO_IDLE, "idle", },
	{ IO_INVALID, "invalid", },
};

const char *ioc_status_name(int st)
{
	unsigned int i;

	for (i = 0; i < sizeof(_status_names)/sizeof(*_status_names); i++) {
		if (st == _status_names[i].st_val)
			return _status_names[i].st_name;
	}
	return "UNKNOWN";
}

struct context;

union event_notify {
	struct {
		pthread_cond_t cond;
		pthread_mutex_t mutex;
	} cv;
	int eventfd;
};

struct request {
	struct iocb iocb;
	enum io_status io_status;
	uint64_t deadline;
	unsigned int refcount;
	struct context *ctx;
	unsigned int idx;
	int notify_type;
	union event_notify notify;
};

static inline int _ioc_get_status(const struct request *req)
{
	cmm_smp_rmb();
	return uatomic_read(&req->io_status);
}

struct context {
	/* This lock protects access to the req member */
	pthread_rwlock_t ctx_lock;
	/* Mutex/cond var for synchronization with event thread */
	pthread_mutex_t event_mutex;
	pthread_cond_t event_cond;
	unsigned int refcount;
	io_context_t aio_ctx;
	pthread_t event_thread;
	timer_t event_timer;
	pthread_mutex_t timer_mutex;
	uint64_t timer_fires;
	bool event_thread_running;
	unsigned int n;
	struct request **req;
};

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

static void __destroy_context(struct context *c)
{
	timer_delete(c->event_timer);
	pthread_rwlock_destroy(&c->ctx_lock);
	pthread_cond_destroy(&c->event_cond);
	pthread_mutex_destroy(&c->timer_mutex);
	pthread_mutex_destroy(&c->event_mutex);
	free(c);
}

static void unref_context(struct context *c)
{
	int n = uatomic_sub_return(&c->refcount, 1);

	if (n == 0)
		__destroy_context(c);
	log(LOG_DEBUG, "ctx -refcount=%d\n", n);
}

static void arm_event_timer(struct context *c, uint64_t time)
{
	struct itimerspec start_it = {
		.it_interval = { 0, },
	};

	if (time == 0)
		return;

	pthread_mutex_lock(&c->timer_mutex);
	pthread_cleanup_push(mutex_unlock, &c->timer_mutex);
	if (time < c->timer_fires) {
		c->timer_fires = time;
		us_to_ts(time, &start_it.it_value);
		if (timer_settime(c->event_timer, TIMER_ABSTIME,
				   &start_it, NULL) != 0)
			log(LOG_WARNING, "%s: failed to arm timer: %m\n",
			    __func__);
		else
			log(LOG_DEBUG, "%s: new expiry: %ld.%06ld\n", __func__,
			    start_it.it_value.tv_sec,
			    start_it.it_value.tv_nsec / 1000);
	}
	pthread_cleanup_pop(1);
}

static void disarm_event_timer(struct context *c)
{
	static const struct itimerspec stop_it = {
		.it_interval = { 0, },
		.it_value = { 0, },
	};

	pthread_mutex_lock(&c->timer_mutex);
	pthread_cleanup_push(mutex_unlock, &c->timer_mutex);
	if (c->timer_fires < UINT64_MAX) {
		c->timer_fires = UINT64_MAX;
		if (timer_settime(c->event_timer, 0, &stop_it, NULL) != 0)
		log(LOG_WARNING, "%s: failed to disarm timer: %m\n",
		    __func__);
	} else
		log(LOG_DEBUG, "%s: disarmed\n", __func__);
	pthread_cleanup_pop(1);
}

static void ref_request(struct request *r)
{
	int n;

	if (!r)
		return;
	 n = uatomic_add_return(&r->refcount, 1);
	 log(LOG_DEBUG + 1, "req %p +refcount=%d\n", r, n);
}

static void unref_request(struct request *r)
{
	int n;

	if (!r)
		return;
	n = uatomic_sub_return(&r->refcount, 1);
	if (n == 0) {
		log(LOG_DEBUG, "%s: freeing request %d, in flight: %s\n",
		    __func__, r->idx,
		    ioc_is_inflight(_ioc_get_status(r)) ? "y" : "n");
		free(r);
	}
	log(LOG_DEBUG + 1, "req %p -refcount=%d\n", r, n);
}

static bool event_notify(struct request *req)
{
	static uint64_t val = 1;

	switch (req->notify_type) {
	case IOC_NOTIFY_EVENTFD:
		write(req->notify.eventfd, &val, sizeof(val));
		log(LOG_DEBUG, "%s: wrote %"PRIu64" to fd=%d\n",
		    __func__, val, req->notify.eventfd);
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

static void wakeup_waiters(struct context *c)
{
	pthread_cond_broadcast(&c->event_cond);
}

/* call with c->ctx_lock write-held */
static void discard_aio_context(struct context *c)
{
	pthread_t et;
	int rc;
	unsigned int i;

	for (i = 0; i < c->n; i++) {
		struct request *req = c->req[i];
		struct io_event ev;

		if (!req || !ioc_is_inflight(_ioc_get_status(req)))
			continue;

		/* This fails always, try nonetheless */
		io_cancel(c->aio_ctx, &req->iocb, &ev);
	}

	pthread_mutex_lock(&c->event_mutex);
	pthread_cleanup_push(mutex_unlock, &c->event_mutex)
	if (c->event_thread_running) {
		et = c->event_thread;
		log(LOG_DEBUG, "cancel event thread %lu\n", et);
		pthread_detach(et);
		rc = pthread_kill(et, SIG_EVSTOP);
		log(LOG_DEBUG, "%s: pthread_kill -> %d\n", __func__, rc);
		rc = pthread_cancel(et);
		log(LOG_DEBUG, "%s: pthread_cancel -> %d\n", __func__, rc);
		while (c->event_thread_running)
			pthread_cond_wait(&c->event_cond, &c->event_mutex);
	}
	pthread_cleanup_pop(1);
}

static int start_event_thread(struct context *c);

static bool restart_io(struct context *c, unsigned int n)
{
	unsigned int i;
	int rc;
	bool need_wake = false;
	uint64_t deadline = UINT64_MAX;

	for (i = 0; i < n; i++) {
		struct request *req = c->req[i];
		struct iocb *iocb;

		if (!req || !ioc_is_inflight(_ioc_get_status(req)))
			continue;

		iocb = &req->iocb;

		ref_request(req);
		rc = io_submit(c->aio_ctx, 1, &iocb);

		if (rc != 1) {
			uatomic_set(&req->io_status, IO_ERR);
			unref_request(req);
			log(LOG_ERR, "%s: io_submit slot %u: %s\n",
			    __func__, i, strerror(-rc));

			need_wake = need_wake || event_notify(req);
		} else {
			uatomic_set(&req->io_status, IO_RUNNING);
			if (req->deadline < deadline)
				deadline = req->deadline;
			log(LOG_DEBUG, "%s: slot %u restarted\n", __func__, i);
		}
	}
	/* The previous io thread, if any, would have disarmed the timer */
	if (deadline < UINT64_MAX)
		arm_event_timer(c, deadline);

	return need_wake;
}

/* Call with c->ctx_lock held */
static int enlarge_context(struct context *c, unsigned int new_n)
{
	struct request **new_req;
	int rc, ret = -1;
	unsigned int old_n;

	if (new_n <= c->n)
		return c->n;

	old_n = c->n;
	new_req = realloc(c->req, new_n * sizeof(*c->req));
	if (new_req == NULL)
		/* Realloc failure - keep current size */
		return c->n;
	memset(&new_req[c->n], 0, (new_n - c->n) * sizeof(*c->req));

	rc = io_setup(new_n, &c->aio_ctx);

	if (rc != 0) {
		log(LOG_WARNING, "%s: io_setup: %s\n",
		    __func__, strerror(rc));
		ret = -rc;
	} else {
		/* need to set this here for event_thread */
		c->n = new_n;
		ret = start_event_thread(c);
		if (ret != 0)
			io_destroy(c->aio_ctx);
	}

	if (ret != 0) {
		log(LOG_ERR, "%s: failed to create context with %d events\n",
		    __func__, new_n);
		free(new_req);
		c->req = NULL;
		c->n = 0;
	} else {
		log(LOG_NOTICE, "%s: context %p/%p set up with %d events\n",
		    __func__, new_req, c->aio_ctx, new_n);
		c->req = new_req;
		ret = new_n;
	}

	if (restart_io(c, old_n))
		wakeup_waiters(c);
	return ret;
}

static int reset_context(struct context *c, unsigned int new_n)
{
	unsigned int i;
	int ret;

	pthread_rwlock_wrlock(&c->ctx_lock);
	pthread_cleanup_push(rwlock_unlock, &c->ctx_lock);
	if (new_n != 0 && c->n >= new_n) {
		/* We currently don't support shrinking */
		ret = new_n;
		goto leave;
	}

	discard_aio_context(c);

	if (new_n > 0)
		ret = enlarge_context(c, new_n);
	else  {
		log(LOG_DEBUG, "%s: checking other requests\n", __func__);
		for (i = 0; i < c->n; i++) {
			struct request *req = c->req[i];

			if (req) {
				c->req[i] = NULL;
				unref_request(req);
				log(LOG_DEBUG, "%s: discarded %d %p\n",
				    __func__, i, req);
			}
		}
		free(c->req);
		c->req = NULL;
		ret = c->n = 0;
	}

leave:
	pthread_cleanup_pop(1);

	return ret;
}

void ioc_destroy_context(struct context *c)
{
	reset_context(c, 0);
	unref_context(c);
}

static void event_timer_notify(union sigval arg)
{
	struct context *ctx = arg.sival_ptr;

	pthread_mutex_lock(&ctx->timer_mutex);
	ctx->timer_fires = UINT64_MAX;
	pthread_mutex_unlock(&ctx->timer_mutex);
	pthread_kill(ctx->event_thread, SIG_EVUPDATE);
	log(LOG_DEBUG, "%s: fired\n", __func__);
}

struct context *ioc_create_context(void)
{
	struct context *c;
	struct sigevent se = {
		.sigev_notify = SIGEV_THREAD,
		.sigev_notify_function = event_timer_notify,
	};

	c = calloc(1, sizeof(struct context));
	if (c == NULL)
		return c;

	if (pthread_mutex_init(&c->event_mutex, NULL))
		goto out_free;

	if (pthread_cond_init(&c->event_cond, NULL))
		goto out_mutex;

	if (pthread_rwlock_init(&c->ctx_lock, NULL))
		goto out_cond;

	se.sigev_value.sival_ptr = c;
	if (timer_create(CLOCK_MONOTONIC, &se, &c->event_timer) != 0) {
		log(LOG_ERR, "%s: timer_create: %m\n", __func__);
		goto out_rwlock;
	}
	if (pthread_mutex_init(&c->timer_mutex, NULL))
		goto out_timer;

	disarm_event_timer(c);

	ref_context(c);
	if (reset_context(c, N_REQUESTS) != N_REQUESTS) {
		unref_context(c);
		return NULL;
	}

	return c;

out_timer:
	timer_delete(c->event_timer);
out_rwlock:
	pthread_rwlock_destroy(&c->ctx_lock);
out_cond:
	pthread_cond_destroy(&c->event_cond);
out_mutex:
	pthread_mutex_destroy(&c->event_mutex);
out_free:
	free(c);
	return NULL;
}

static void release_aio_slot(struct context *ctx, unsigned int n)
{
	pthread_rwlock_rdlock(&ctx->ctx_lock);
	pthread_cleanup_push(rwlock_unlock, &ctx->ctx_lock);
	if (n < ctx->n) {
		unref_request(ctx->req[n]);
		ctx->req[n] = NULL;
	}
	pthread_cleanup_pop(1);
	log(LOG_DEBUG, "%s: released %u/%u\n", __func__, n, ctx->n);
	unref_context(ctx);
}

static unsigned int alloc_aio_slot(struct context *ctx, struct request *req)
{
	int i, n, retries = 3;

	assert(ctx->n > 0 && req != NULL);
	do {
		pthread_rwlock_rdlock(&ctx->ctx_lock);
		pthread_cleanup_push(rwlock_unlock, &ctx->ctx_lock)
		n = ctx->n;
		for (i = 0; i < n; i++) {
			if (ctx->req[i] == NULL) {
				ctx->req[i] = req;
				ref_request(req);
				ref_context(ctx);
				log(LOG_DEBUG, "%s: found slot: %d/%d\n",
				    __func__, i, n);
				break;
			}
		}
		pthread_cleanup_pop(1);
		if (i < n)
			return i;
	} while (retries-- > 0 && reset_context(ctx, n + N_REQUESTS) > n);

	return INVALID_SLOT;
}

int ioc_reset(struct iocb *iocb)
{
	struct request *req;
	if (!iocb) {
		errno = EINVAL;
		return -1;
	}

	req = container_of(iocb, struct request, iocb);
	switch (_ioc_get_status(req)) {
	case IO_RUNNING:
	case IO_TIMEOUT:
		errno = EBUSY;
		return -1;
	default:
		/* No race possible here, the event thread only operates
		   on RUNNING or TIMEOUT state */
		uatomic_set(&req->io_status, IO_IDLE);
		return 0;
	}
}

int ioc_submit(struct iocb *iocb, const struct timespec *deadline)
{
	struct request *req;
	struct context *ctx;
	int rc, ret;

	if (!iocb) {
		errno = EINVAL;
		return -1;
	}

	req = container_of(iocb, struct request, iocb);
	if (_ioc_get_status(req) != IO_IDLE) {
		errno = EBUSY;
		return -1;
	}
	ctx = req->ctx;

	req->deadline = deadline ? ts_to_us(deadline) : UINT64_MAX;

	pthread_rwlock_rdlock(&ctx->ctx_lock);
	pthread_cleanup_push(rwlock_unlock, &ctx->ctx_lock);

	uatomic_set(&req->io_status, IO_RUNNING);
	ref_request(req);

	rc = io_submit(ctx->aio_ctx, 1, &iocb);

	if (rc != 1) {
		ret = -1;
		errno = -rc;
		uatomic_set(&req->io_status, IO_ERR);
		unref_request(req);
		log(LOG_ERR, "%s: io_submit (%p): %s\n",
		    __func__, ctx->aio_ctx, strerror(-rc));
	} else {
		ret = 0;
		arm_event_timer(ctx, req->deadline);
		log(LOG_DEBUG, "%s: io submitted for job %u\n",
			      __func__, req->idx);
	}

	pthread_cleanup_pop(1);

	return ret;
}

int ioc_get_status(const struct iocb *iocb)
{
	const struct request *req;

	if (!iocb)
		return IO_INVALID;

	req = container_of(iocb, const struct request, iocb);
	return _ioc_get_status(req);
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
		    "%s: (%d) read %" PRIu64 " from fd=%d\n",
		    __func__,rc, rc > 0 ? val : (uint64_t)0, fd);
	}
}

static inline int ioc_wait_for_cond(unsigned int mask, struct request *req,
				    pthread_cond_t *cond,
				    pthread_mutex_t *mutex)
{
	int _rv;

	pthread_mutex_lock(mutex);
	pthread_cleanup_push(mutex_unlock, mutex);
	while (((_rv = _ioc_get_status(req)) & mask) == 0)
		pthread_cond_wait(cond, mutex);
	pthread_cleanup_pop(1);
	return _rv;
}


static int _ioc_wait(struct iocb *iocb, int *st, unsigned int mask)
{
	struct request *req;
	uint64_t val;
	int rc = 0, rv = 0;

	if (!iocb) {
		errno = EINVAL;
		return -1;
	}

	req = container_of(iocb, struct request, iocb);
	log(LOG_DEBUG, "%s: type = %d val=%d mask=%08x\n", __func__,
	    req->notify_type, _ioc_get_status(req), mask);

	switch (req->notify_type) {
	case IOC_NOTIFY_COMMON:
		rv = ioc_wait_for_cond(mask, req,
				       &req->ctx->event_cond,
				       &req->ctx->event_mutex);
		break;
	case IOC_NOTIFY_COND:
		rv = ioc_wait_for_cond(mask, req,
				       &req->notify.cv.cond,
				       &req->notify.cv.mutex);
		break;
	case IOC_NOTIFY_EVENTFD:
		eat_pending_events(req->notify.eventfd);
		while (((rv = _ioc_get_status(req)) & mask) == 0) {
			struct pollfd pf = {
				.fd = req->notify.eventfd,
				.events = POLLIN,
			};

			do {
				rc = poll(&pf, 1, -1);
			} while (rc == -1 && errno == EAGAIN);

			if (rc == -1) {
				log(LOG_ERR, "%s: poll: %m\n",
				    __func__);
				break;
			}
			log(LOG_DEBUG + 1, "%s sts=%x=%s\n", __func__, rv,
			    ioc_status_name(rv));
			rc = read(req->notify.eventfd, &val, 8);
			log(LOG_DEBUG,
			    "%s: (%d) read %"PRIu64" from fd=%d\n",
			    __func__, rc, rc > 0 ? val : (uint64_t)0,
			    req->notify.eventfd);
			if (rc > 0) {
				rc = 0;
			} else {
				log(LOG_ERR, "%s: read: %m\n",
				    __func__);
				break;
			}
		}
		break;
	default:
		errno = -EINVAL;
		return -1;
	}

	log(LOG_DEBUG, "%s: rc=%d rv=%d\n", __func__, rc, rv);
	if (rc != 0)
		log(LOG_ERR, "%s: error: %m\n", __func__);
	else if (st)
		*st = rv;
	return rc;
}

int ioc_wait_done(struct iocb *iocb, int *st) {
	return _ioc_wait(iocb, st, ~IO_TIMEOUT);
}

int ioc_wait_event(struct iocb *iocb, int *st) {
	return _ioc_wait(iocb, st, ~0);
}

int ioc_get_eventfd(const struct iocb *iocb) {
	const struct request *req;

	if (iocb == NULL) {
		errno = EINVAL;
		return -1;
	}
	req = container_of_const(iocb, struct request, iocb);
	if (req->notify_type != IOC_NOTIFY_EVENTFD) {
		errno = EINVAL;
		return -1;
	}
	return req->notify.eventfd;
}

void ioc_put_iocb(struct iocb *iocb)
{
	struct request *req;
	struct context *ctx;
	unsigned int type;

	if (!iocb)
		return;
	req = container_of(iocb, struct request, iocb);
	ctx = req->ctx;
	type = req->notify_type;

	/* avoid further notifcations to be sent */
	req->notify_type = IOC_NOTIFY_NONE;
	switch (type) {
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

	release_aio_slot(ctx, req->idx);
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
	req = container_of(iocb, struct request, iocb);
	switch (type) {
	case IOC_NOTIFY_COND:
		rv = pthread_cond_init(&req->notify.cv.cond, NULL);
		if (rv != 0) {
			log(LOG_ERR,
			    "%s: error initializing condition variable",
			    __func__);
			errno = rv;
			return -1;
		}
		rv = pthread_mutex_init(&req->notify.cv.mutex, NULL);
		if (rv != 0) {
			log(LOG_ERR,
			    "%s: error initializing mutex", __func__);
			pthread_cond_destroy(&req->notify.cv.cond);
			errno = rv;
			return -1;
		}
		break;
	case IOC_NOTIFY_EVENTFD:
		req->notify.eventfd = eventfd(0, 0);
		if (req->notify.eventfd == -1) {
			log(LOG_ERR, "%s: eventfd: %m\n", __func__);
			return -1;
		}
		log(LOG_DEBUG, "%s: job %d fd=%d\n", __func__,
		    req->idx, req->notify.eventfd);
		break;
	case IOC_NOTIFY_NONE:
	case IOC_NOTIFY_COMMON:
		break;
	default:
		log(LOG_ERR, "%s: invalid notification type: %u\n", __func__,
		    type);
		errno = EINVAL;
		return -1;
	}
	req->notify_type = type;
	return 0;
}

struct iocb *ioc_new_iocb(struct context *ctx, enum ioc_notify_type type)
{
	struct request *req;
	unsigned int n;

	req = calloc(1, sizeof(*req));
	if (!req)
		return NULL;

	uatomic_set(&req->io_status, IO_IDLE);

	req->ctx = ctx;
	/* alloc_aio_slot() increases refcount */
	n = alloc_aio_slot(ctx, req);
	if (n == INVALID_SLOT) {
		log(LOG_ERR, "%s: failed to allocate slot\n", __func__);
		errno = ERANGE;
		free(req);
		return NULL;
	}
	req->idx = n;
	if (ioc_set_notify(&req->iocb, type) != 0) {
		unref_request(req);
		return NULL;
	}
	return &req->iocb;
}

static bool handle_completions(int n, const struct io_event *events)
{
	int i;
	bool action_needed = false;

	for (i = 0; i < n; i++) {
		struct request *req;

		req = container_of(events[i].obj, struct request,
				   iocb);

		uatomic_or(&req->io_status, IO_DONE);

		log(LOG_DEBUG,
		    "%s: req %u compl: st=%s %ld %lu ofs=%lld\n",
		    __func__, req->idx, ioc_status_name(_ioc_get_status(req)),
		    events[i].res, events[i].res2,
		    events[i].obj->u.c.offset);

		action_needed = action_needed || event_notify(req);
	}

	return action_needed;
}

static void event_thread_cleanup(void *arg)
{
	struct context *ctx = arg;
	io_context_t trash_ctx;
	unsigned int i;

	disarm_event_timer(ctx);

	/* Drop "in-flight" refs held by the IO thread */
	/* FIXME: is this correct? */
	for (i = 0; i < ctx->n; i ++) {
		if (ctx->req[i] &&
		    ioc_is_inflight(_ioc_get_status(ctx->req[i])))
			unref_request(ctx->req[i]);
	}
	trash_ctx = ctx->aio_ctx;
	ctx->aio_ctx = 0;

	/* Tell them we're leaving */
	pthread_mutex_lock(&ctx->event_mutex);
	ctx->event_thread_running = false;
	pthread_cond_broadcast(&ctx->event_cond);
	pthread_mutex_unlock(&ctx->event_mutex);

	unref_context(ctx);
	io_destroy(trash_ctx);
	log(LOG_NOTICE, "%s: done, released %p\n", __func__, trash_ctx);
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

static void *event_thread(void *arg)
{
	struct context *ctx = arg;
	sigset_t mask;
	bool _exit = false;
	static const struct sigaction stop_sa =
		{ .sa_handler = event_stop_handler, };
	static const struct sigaction upd_sa =
		{ .sa_handler = event_upd_handler, };
	static const struct sigaction ign_sa =
		{ .sa_handler = SIG_IGN, };

	if (ctx->n == 0)
		return NULL;

	sigfillset(&mask);
	if (pthread_sigmask(SIG_SETMASK, &mask, NULL) != 0) {
		log(LOG_ERR, "%s: pthread_sigmask: %m\n", __func__);
		return NULL;
	}

	pthread_setspecific(exit_key, &_exit);
	if (sigaction(SIG_EVSTOP, &stop_sa, NULL) != 0) {
		log(LOG_ERR, "%s: sigaction STOP: %m\n", __func__);
		return NULL;
	}
	if (sigaction(SIG_EVUPDATE, &ign_sa, NULL) != 0)
		log(LOG_ERR, "%s: sigaction UPDATE: %m\n", __func__);

	sigdelset(&mask, SIG_EVSTOP);
	sigdelset(&mask, SIG_EVUPDATE);

	ref_context(ctx);
	pthread_cleanup_push(event_thread_cleanup, ctx);

	pthread_mutex_lock(&ctx->event_mutex);
	ctx->event_thread = pthread_self();
	ctx->event_thread_running = true;
	pthread_cond_broadcast(&ctx->event_cond);
	pthread_mutex_unlock(&ctx->event_mutex);
	log(LOG_INFO, "%s: starting\n", __func__);

	for (;;) {
		struct io_event events[N_EVENTS];
		struct timespec ts;
		uint64_t now, max_wait;
		unsigned int i;
		int rc;
		bool action_needed = false;
		bool must_quit = false;
		struct request *req;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		now = ts_to_us(&ts);
		max_wait = UINT64_MAX - MAX_WAIT_US > now ?
			now + MAX_WAIT_US : UINT64_MAX;

		while (pthread_rwlock_tryrdlock(&ctx->ctx_lock) != 0) {
			pthread_testcancel();
			sched_yield();
		}
		pthread_cleanup_push(rwlock_unlock, &ctx->ctx_lock);

		if (!ctx->req) {
			log(LOG_NOTICE, "%s: empty context\n", __func__);
			must_quit = true;
		} else {
			for (i = 0; i < ctx->n; i++) {
				req = ctx->req[i];
				if (!req)
					continue;
				if (req->deadline < now + BLINK) {
					if (uatomic_cmpxchg(&req->io_status,
							    IO_RUNNING, IO_TIMEOUT)
					    == IO_RUNNING) {
						action_needed = action_needed ||
							event_notify(req);
						log(LOG_DEBUG, "%s: job %u: timed out, sts=%s\n",
						    __func__, req->idx,
						    ioc_status_name(_ioc_get_status(req)));
					}
				} else if (req->deadline < max_wait &&
					   ioc_is_inflight(_ioc_get_status(req)))
					max_wait = req->deadline;
			}
		}
		pthread_cleanup_pop(1);
		if (must_quit)
			break;

		if (action_needed) {
			wakeup_waiters(ctx);
			log(LOG_DEBUG, "%s: tmo: %" PRIu64 "\n", __func__, now);
			action_needed = false;
		}

		arm_event_timer(ctx, max_wait + TIMER_EXTRA_US);

		max_wait -= now;
		us_to_ts(max_wait, &ts);

		pthread_testcancel();

		log(LOG_DEBUG, "%s: timeout = %" PRIu64 "us\n",
		    __func__, max_wait);

		/* If io_pgetevents returns anything, we need to act on it */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

		if (sigaction(SIG_EVUPDATE, &upd_sa, NULL) != 0)
			log(LOG_ERR, "%s: sigaction (enable update sig): %m",
			    __func__);
		rc = io_pgetevents(ctx->aio_ctx, 1, N_EVENTS, events, &ts,
				   &mask);
		if (sigaction(SIG_EVUPDATE, &ign_sa, NULL) != 0)
			log(LOG_ERR, "%s: sigaction (disable update sig): %m",
			    __func__);

		if (rc == -EINVAL) {
			log(LOG_WARNING, "%s: io_pgetevents: EINVAL\n",
			    __func__);
			break;
		} else if (rc == -EINTR) {
			if (uatomic_read(&_exit)) {
				log(LOG_NOTICE, "%s: exit signal received\n",
				    __func__);
				break;
			} else {
				log(LOG_DEBUG, "%s: update signal received\n",
				    __func__);
			}
		} else if (rc < 0) {
			log(LOG_ERR, "%s: io_pgetevents: retcode = %d\n",
			    __func__, rc);
			break;
		}

		action_needed = action_needed || handle_completions(rc, events);
		if (action_needed)
			wakeup_waiters(ctx);

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		if (must_quit)
			break;
		pthread_testcancel();
	}
	pthread_cleanup_pop(1);
	return NULL;
}

static int start_event_thread(struct context *c)
{
	pthread_t pt;
	int rc;

	pthread_mutex_lock(&c->event_mutex);
	rc = pthread_create(&pt, NULL, event_thread, c);
	if (rc != 0) {
		pthread_mutex_unlock(&c->event_mutex);
		log(LOG_ERR, "%s: pthread_create: %m", __func__);
		pthread_mutex_unlock(&c->event_mutex);
		return rc;
	}

	while (!c->event_thread_running)
		pthread_cond_wait(&c->event_cond, &c->event_mutex);

	pthread_mutex_unlock(&c->event_mutex);
	log(LOG_DEBUG, "%s: created event thread %ld\n", __func__, pt);
	return 0;
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
		log(LOG_ERR, "%s: Invalid value for %s: %s\n", __func__,
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
