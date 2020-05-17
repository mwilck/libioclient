#ifndef _IOC_INTERNAL_H
#define _IOC_INTERNAL_H 1

/*
 * These must be thisjunct with ioc_status!
 * @IOI_ERR:	Error during iocb submission
 * @IOI_IDLE:	Idle, ready for submission
 * @IOI_DISCARDED: Released by application
 * @IOI_INVALID:	invalid iocb pointer
 */
enum ioc_int_status {
	IOI_PUBLIC_MASK = IOC_TIMEOUT | IOC_DONE,
	IOI_ERR       = (1 <<  2),
	IOI_DISCARDED = (1 <<  4),
	IOI_INVALID   = (1 <<  8),
};

#define INVALID_SLOT ~0U

#define container_of(ptr, type, member) ({		\
			typeof( ((type *)0)->member ) *__mptr = (ptr);	\
			(type *)( (char *)__mptr - offsetof(type,member) );})
#define container_of_const(ptr, type, member) ({		\
			typeof( ((const type *)0)->member ) *__mptr = (ptr); \
			(const type *)( (const char *)__mptr - \
					offsetof(type,member) );})

struct context;

union event_notify {
	struct {
		pthread_cond_t cond;
		pthread_mutex_t mutex;
	} cv;
	ioc_notify_callback cb;
	int eventfd;
};

struct request {
	struct iocb iocb;
	unsigned int refcount;
	int io_status;
	uint64_t deadline;
	struct context *ctx;
	unsigned int idx;
	int notify_type;
	union event_notify notify;
	/* for discarded events */
	void (*free_resources)(struct iocb*);
};

struct aio_group {
	io_context_t aio_ctx;
	unsigned int index;
	unsigned int nr_reqs;
	/* This lock protects access to the req member */
	pthread_mutex_t req_mutex;
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

static inline struct context *group2context(struct aio_group *grp)
{
	return grp->ctx;
}

static inline struct request *iocb2request(struct iocb *iocb)
{
	return iocb ? container_of(iocb, struct request, iocb) : NULL;
}

static inline const struct request *iocb2request_const(const struct iocb *iocb)
{
	return iocb ? container_of(iocb, const struct request, iocb) : NULL;
}

static inline int req_get_int_status(const struct request *req)
{
	cmm_smp_rmb();
	return uatomic_read(&req->io_status);
}

static inline bool __ioc_is_inflight(int st) {
	return !(st & IOC_DONE);
}

static inline bool req_is_inflight(const struct request *req)
{
	return __ioc_is_inflight(req_get_int_status(req));
}

static inline bool __ioc_has_timed_out(int st) {
	return (st & IOC_TIMEOUT);
}

static inline bool req_has_timed_out(const struct request *req)
{
	return __ioc_has_timed_out(req_get_int_status(req));
}

#endif /* _IOC_INTERNAL_H */
