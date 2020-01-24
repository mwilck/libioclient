#ifndef _IOC_H
#define _IOC_H

#define _IO_RUNNING_SHIFT 8
#define _IO_RUNNING (1 << _IO_RUNNING_SHIFT)
#define IO_STATUS_MASK (_IO_RUNNING - 1)

/**
 * enum io_status - the "result" of an I/O operation
 * @IO_UNUSED:  not in use
 * @IO_IDLE:    idle, no I/O in flight recently
 * @IO_PENDING: waiting for I/O to either complete or time out
 * @IO_OK:      I/O completed successfully
 * @IO_TMO:     timeout occured, I/O may still be in flight
 * @IO_BAD:     an error occured, details in iocb fields
 */
enum io_status {
	IO_UNUSED,
	IO_IDLE,
	IO_PENDING,
	IO_OK,
	IO_TMO,
	IO_BAD,
};

/**
 * ioc_status_name() - printed representation of an enum &io_status
 * @st: an &io_status value
 *
 * Return: character string representing the status
 */
const char *ioc_status_name(unsigned int st);

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
 * ioc_destroy_context() - destroy a context object
 * @ctx: pointer to context object
 *
 * Use this function to free the resources used by a context
 * previously allocated with ioc_create_context(). The event
 * thread is stopped, notifications will no longer work. No
 * new IO can be submitted to the context. In-flight IO will
 * continue. The resources are eventually freed when all
 * iocbs are released by the application (using ioc_put_iocb()),
 * and when in-flight IO is completed.
 */
void ioc_destroy_context(struct context *c);

/**
 * ioc_new_iocb() - create an iocb object
 * @ctx: context in which to create the iocb
 *
 * This function creates the basic unit for I/O in libioclient,
 * the iocb. The data structure is the same as in libaio.
 * The libaio functions io_prep_pread() and io_prep_pwrite()
 * can be used to initialize &iocb objects for actual I/O.
 */
struct iocb *ioc_new_iocb(struct context *ctx);

/**
 * ioc_put_iocb() - discard an iocb object
 * @arg: pointer to an iocb object
 *
 * Drop a reference to an iocb object that is no longer used, and
 * detach it from the context it was created on.
 * The argument is define as ``void*`` to make it possible to pass this
 * function to pthread_cleanup_push() without casting. The iocb
 * object can't be accessed any more, but will continue to exist
 * until possible in-flight IO completes. Notifications for this iocb
 * will not be sent any more after ioc_put_iocb() has been called.
 */
void ioc_put_iocb(void *arg);

/**
 * enum ioc_notify_type - notification type for iocb objects
 * @IOC_NOTIFY_COMMON:   use a condition variable shared by the all iocbs in
 *                       the context. This is the default.
 * @IOC_NOTIFY_COND:     use a iocb-specific condition variable.
 *                       This is less prone to contention. It requires a mutex
 *                       that is controlled by the application.
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
 * ioc_set_notify() - set notification method for an iocb
 * @iocb:     iocb object to act on
 * @type:     enum &ioc_notify_type value, see above.
 * @condvar:  an initialized pthreads condition variable to use
 *            (only for &IOC_NOTIFY_COND).
 * @eventd:   the file descriptor for the eventfd to use, must
 *            have been opened with ``eventfd``
 *            (only for &IOC_NOTIFY_EVENTFD).
 *
 * This function sets the desired notification method for the
 * iocb (see enum &ioc_notify_type), and its parameters. Parameters 
 * that are unused by the chosen method are ignored.
 *
 * Return: 0 on success. On error, -1 is returned, and errno is
 *         set to an error code. Supported error code: -EINVAL.
 */
int ioc_set_notify(struct iocb *iocb, unsigned int type,
		   pthread_cond_t *condvar, int eventfd);

/**
 * ioc_submit() - submit I/O
 * @iocb:      iocb to submit
 * @deadline:  timeout for this iocb
 *
 * Submit an iocb, which should have been prepared for aio e.g. using
 * the libaio convenience functions io_prep_pread() and io_prep_pwrite().
 * unlike io_submit(), only a single iocb can be submitted at one time.
 * The @deadline parameter specifies the timeout for this I/O request,
 * as absolute time using the ``CLOCK_MONOTONIC`` system clock.
 * Pass ``NULL`` for @deadline to set no timeout. If the timeout has
 * expired already when ioc_submit() is called, a timeout notification
 * will be signalled immediately. Immediately after calling io_submit(),
 * the iocb will be "running", and the status will be &IO_PENDING.
 */
int ioc_submit(struct iocb *iocb, const struct timespec *deadline);


/**
 * ioc_status() - get status value from ioc_get_status() return code
 * @st: return value from ioc_get_status() or ioc_wait_complete()
 *
 * Return: the status byte (enum &io_status) from @st.
 */
static inline int ioc_status(int st) {
	return (st & IO_STATUS_MASK);
}

/**
 * ioc_is_running() - check if I/O is still in flight
 * @st: return value from ioc_get_status() or ioc_wait_complete()
 *
 * Return: ``true`` if I/O is in flight. ioc_submit() may only be
 *         called on this iocb after this returns ``false``.
 */
static inline bool ioc_is_running(int st) {
	return !!(st & _IO_RUNNING);
}

/**
 * ioc_get_status() - retrieve current status of iocb
 * @iocb: An iocb object
 *
 * Call ioc_status() and ioc_is_running() on the return value
 * of this function to interpret the value.
 *
 * Return: a combined value representing the &io_status and the
 *         informatin whether I/O is still in flight. This value
 *         is positive. -1 if an invalid iocb object is detected.
 */
int ioc_get_status(const struct iocb *iocb);

/**
 * ioc_wait_complete() - wait until iocb status is known
 * @iocb:    the iocb to wait on
 * @mutex:   the mutex to use (IOC_NOTIFY_COND only)
 *
 * This function waits on an iocb until its status has reached a
 * "result" value, IOW the stauts is not &IO_PENDING any more.
 * When this function returns after io_submit() had been called,
 * the status is either &IO_OK, &IO_BAD, or &IO_TMO. In the latter case,
 * I/O is usually still in flight when this function returns.
 *
 * Return: See ioc_get_status().
 */

int ioc_wait_complete(struct iocb *iocb, pthread_mutex_t *mutex);

/**
 * ioc_wait_idle() - wait until more I/O can be submitted
 * @iocb:    the iocb to wait on
 * @mutex:   the mutex to use (IOC_NOTIFY_COND only)
 *
 * This function waits until I/O in flight completes. If it returns
 * success, the status is guaranteed to be &IO_IDLE, and ioc_is_running()
 * is guaranteed to return ``false``, until ioc_submit() is called again.
 * For notification method &IOC_NOTIFY_COND, an initialized, unlocked mutex
 * has to be passed in the @mutex parameter, which is ignored for other
 * notificatin methods.
 *
 * Return: 0 in case of success. -1 in case of failure.
 *         Error code: -EINVAL: called for notification type &IOC_NOTIFY_NONE.
 *         For IOC_NOTIFY_EVENTFD, other errno values as set by read()
 *         and poll() are possible.
 */
int ioc_wait_idle(struct iocb *iocb, pthread_mutex_t *mutex);

#endif /* _IOC_H */
