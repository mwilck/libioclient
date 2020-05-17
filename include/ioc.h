#ifndef _IOC_H
#define _IOC_H

#define _IO_RUNNING_SHIFT 8
#define _IO_RUNNING (1 << _IO_RUNNING_SHIFT)
#define IO_STATUS_MASK (_IO_RUNNING - 1)

/**
 * enum io_status - the "result" of an I/O operation
 * @IO_DONE:    ready for submission (idle or done)
 * @IO_RUNNING: I/O submitted, in flight
 * @IO_TIMEOUT: Timed out
 * @IO_ERR:	Error during iocb submission
 * @IO_IDLE:	Idle, ready for submission
 * @IO_INVALID:	invalid iocb pointer
 */
enum io_status {
	IO_RUNNING   = 0,
	IO_TIMEOUT   = (1 <<  0),
	IO_DONE      = (1 <<  1),
	IO_ERR       = (1 <<  2),
	IO_IDLE      = (1 <<  4),
	IO_DISCARDED = (1 <<  8),
	IO_INVALID   = (1 << 16),
};

/**
 * ioc_status_name() - printed representation of an enum &io_status
 * @st: an &io_status value
 *
  * Return: character string representing the status
 */
const char *ioc_status_name(int st);

struct context;
struct iocb;
struct timespec;

/**
 * libioc_init() - initialize libioclient
 *
 * Call this before making any other calls to functions of this
 * library.
 *
 * Return: 0
 */
int libioc_init(void);

/**
 * ioc_create_context() - create a new context for libioc requests
 *
 * At least one context is necessary to submit iocbs. An event
 * handling thread and an aio context are associated with the context.
 *
 * Return: Pointer to a newly allocated context if successful.
 *         NULL, otherwise.
 */
struct context *ioc_create_context(void);

/**
 * ioc_put_context() - destroy a context object
 * @ctx: pointer to context object
 *
 * Tell the library that this context will no longer be used
 * by the application. After calling this function, ioc_submit()
 * and ioc_new_iocb() can't be called any more for this context.
 * The user must still call ioc_put_iocb() on all iocbs that are
 * no longer used, even if they have completed. When all iocbs
 * are released and all IO has completed, the resources used by
 * the context will be freed.
 */
void ioc_put_context(struct context *c);

/**
 * enum ioc_notify_type - notification type for iocb objects
 * @IOC_NOTIFY_COMMON:   use a condition variable shared by the all iocbs in
 *                       the context.
 * @IOC_NOTIFY_COND:     use a iocb-specific condition variable.
 *                       This is less prone to contention.
 * @IOC_NOTIFY_EVENTFD:  use a linux  ``eventfd`` which is created by the
 *                       application.
 * @IOC_NOTIFY_NONE:     Don't use notification.
 */
enum ioc_notify_type {
	IOC_NOTIFY_COMMON,
	IOC_NOTIFY_COND,
	IOC_NOTIFY_EVENTFD,
	IOC_NOTIFY_NONE,
};

/**
 * ioc_is_inflight() - check if IO is in flight for iocb
 * @st: return value from ioc_get_status() or ioc_wait_complete()
 *
 * Return: ``true`` if I/O is in flight.
 */
static inline bool __ioc_is_inflight(int st) {
	return !(st & IO_DONE);
}

/**
 * ioc_new_iocb() - create an iocb object
 * @ctx: context in which to create the iocb
 * @type: enum &ioc_notify_type value, see above.
 * @free_resources: a function that will be called when the IO completes
 *
 * This function creates the basic unit for I/O in libioclient,  the iocb.
 * The data structure is the same as in libaio.
 * The libaio functions io_prep_pread() and io_prep_pwrite()
 * can be used to initialize &iocb objects for actual I/O.
 *
 * free_resources() is the pointer to a cleanup function. This function will
 * be called when ioc_put_iocb() is called, if no IO is inflight at that time,
 * or when in-flight IO completes after calling ioc_put_iocb(). The function
 * should release remaining dynamically allocated resources of the iocb
 * (e.g. buffers). These buffers must not be released / freed by the calling
 * program before the IO has completed.
 * Pass NULL for free_resources if resource freeing at completion is not
 * necessary or not desired.
 *
 * Return: a new iocb in case of success, NULL otherwise.
 */
struct iocb *ioc_new_iocb(struct context *ctx, enum ioc_notify_type type,
			  void (*free_resources)(struct iocb*));

/**
 * ioc_get_eventfd() - obtain iocb's eventfd
 * @iocb: pointer to an iocb object
 *
 * Return the iocb's eventfd, to be used in the application using select(),
 * poll(), epoll() or similar. The returned file descriptor shouldn't be used
 * any more after calling ioc_put_iocb() on this iocb.
 *
 * Return:
 * The iocb's event fd on success, -1 on failure.
 * Error code: EINVAL: The notifcation type of this iocb was not
 *	IOC_NOTIFY_EVENTFD.
 */
int ioc_get_eventfd(const struct iocb *iocb);

/**
 * ioc_put_iocb() - discard an iocb object
 * @iocb: pointer to an iocb object
 *
 * Drop a reference to an iocb object that is no longer used
 * The iocb object can't be accessed any more, but will continue to exist
 * until possible in-flight IO completes. Notifications for this iocb will not
 * be sent any more after ioc_put_iocb() has been called.
 */
void ioc_put_iocb(struct iocb *iocb);

/**
 * ioc_put_iocb_cleanup() - discard an iocb object
 * @arg: pointer to an iocb object
 *
 * This is exactly like ioc_put_iocb, except for the function prototype.
 * The argument is define as ``void*`` to make it possible to pass this
 * function to pthread_cleanup_push() without casting.
 */
void ioc_put_iocb_cleanup(void *arg);

/**
 * ioc_submit() - submit I/O
 * @iocb:      iocb to submit
 * @deadline:  timeout for this iocb
 *
 * Submit an iocb, which should have been prepared for aio e.g. using
 * the libaio convenience functions io_prep_pread() and io_prep_pwrite().
 * If the iocb has been submitted before, ioc_reset() must be called before
 * submitting it again.
 * unlike io_submit(), only a single iocb can be submitted at one time.
 * The @deadline parameter specifies the timeout for this I/O request,
 * as relative time in microseconds, using the ``CLOCK_MONOTONIC`` system clock.
 * Pass 0 for @deadline to set no timeout.
 * After calling io_submit(), the iocb will be "running", and the status will be
 * &IO_PENDING.
 *
 * Return:
 * 0 on success, -1 on failure (sets errno).
 * Errno values: EINVAL: invalid iocb pointer. EBUSY: iocb is busy, call
 * ioc_reset() first. Other values: see io_submit().
 */
int ioc_submit(struct iocb *iocb, uint64_t deadline);

/**
 * ioc_reset() - reset iocb status before new submission
 * @iocb:      iocb to reset
 *
 * An application calls this function on a previously submitted and completed iocb.
 * This tells the librarry that the application is done processing the result.
 *
 * Return:
 * 0 on success, -1 on failure. errno values: EINVAL: invalid iocb passed.
 * EBUSY: I/O is still in flight, resetting isn't possible.
 */
int ioc_reset(struct iocb *iocb);

/**
 * ioc_get_status() - retrieve current status of iocb
 * @iocb: An iocb object
 *
 * Call ioc_status() and ioc_is_running() on the return value
 * of this function to interpret the value.
 *
 * Return: a combined value representing the &io_status.
 *         IO_INVALID if an invalid iocb object is detected.
 */
int ioc_get_status(const struct iocb *iocb);

static inline bool ioc_is_inflight(const struct iocb *iocb)
{
	return __ioc_is_inflight(ioc_get_status(iocb));
}

/**
 * ioc_wait_event() - wait for completion or timeout
 * @iocb:    the iocb to wait on
 * @st:	     pointer for io_status
 *
 * This function waits on an iocb until its status has either
 * completed or timed out. If the function is successful and ``st``
 * is non-null, the io_status after waiting is stored in ``st``.
 *
 * Return: See ioc_wait_done().
 */
int ioc_wait_event(struct iocb *iocb, int *st);

/**
 * ioc_wait_done() - wait until completion
 * @iocb:    the iocb to wait on
 * @st:	     pointer for io_status
 *
 * This function waits until I/O in flight completes. If it returns
 * success, ioc_is_ready() is guaranteed to return ``true``.
 * If the function is successful and ``st`` is non-null, the io_status after
 * waiting is stored in ``st``.
 *
 * Return: 0 in case of success. -1 in case of failure.
 *         Error code: -EINVAL: called for notification type &IOC_NOTIFY_NONE.
 *         For IOC_NOTIFY_EVENTFD, other errno values as set by read()
 *         and poll() are possible.
 */
int ioc_wait_done(struct iocb *iocb, int *st);

#endif /* _IOC_H */
