#ifndef _IOC_H
#define _IOC_H

#define _IO_RUNNING_SHIFT 8
#define _IO_RUNNING (1 << _IO_RUNNING_SHIFT)
#define IO_STATUS_MASK (_IO_RUNNING - 1)
enum io_status {
	IO_UNUSED,
	IO_IDLE,
	IO_PENDING,
	IO_OK,
	IO_TMO,
	IO_BAD,
};

const char *ioc_status_name(unsigned int st);

static inline int ioc_status(int st) {
	return (st & IO_STATUS_MASK);
}

static inline bool ioc_is_running(int st) {
	return !!(st & _IO_RUNNING);
}

enum {
	IOC_NOTIFY_COMMON,
	IOC_NOTIFY_COND,
	IOC_NOTIFY_EVENTFD,
	IOC_NOTIFY_NONE,
};

struct context;
struct iocb;
struct timespec;

int libioc_init(void);

struct context *ioc_create_context(void);
void ioc_destroy_context(struct context *c);

struct iocb *ioc_new_iocb(struct context *ctx);
int ioc_set_notify(struct iocb *iocb, unsigned int type,
		   pthread_cond_t *condvar, int eventfd);
void ioc_put_iocb(void *arg);

int ioc_submit(struct iocb *iocb, const struct timespec *deadline);
int ioc_get_status(const struct iocb *iocb);
int ioc_wait_idle(struct iocb *iocb, pthread_mutex_t *mutex);
int ioc_wait_complete(struct iocb *iocb, pthread_mutex_t *mutex);

#endif /* _IOC_H */
