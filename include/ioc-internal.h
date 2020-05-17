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
	IOI_IDLE      = (1 <<  4),
	IOI_DISCARDED = (1 <<  8),
	IOI_INVALID   = (1 << 16),
};

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

static inline struct request *iocb2request(struct iocb *iocb)
{
	return iocb ? container_of(iocb, struct request, iocb) : NULL;
}

static inline const struct request *iocb2request_const(const struct iocb *iocb)
{
	return iocb ? container_of(iocb, const struct request, iocb) : NULL;
}

#endif /* _IOC_INTERNAL_H */
