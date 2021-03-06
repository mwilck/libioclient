/*
 * Copyright (c) 2020 Martin Wilck, SUSE Software Solutions GmbH
 * SPDX-license-identifier: LGPL-2.1-or-later
 */

#ifndef _IOC_H
#define _IOC_H
#include <stdint.h>
#include <stdbool.h>

struct context;
struct iocb;

/**
 * enum ioc_int_status - the "result" of an I/O operation
 * This is the internal status
 * @IOC_DONE:    ready for submission (idle or done)
 * @IOC_RUNNING: I/O submitted, in flight
 * @IOC_TIMEOUT: Timed out
 *
 * Note: @IOC_DONE does not imply *successful* completion. Check the
 * iocb status flags for the result of the IO.
 */
enum ioc_status {
	IOC_RUNNING   = 0,
	IOC_TIMEOUT   = (1 <<  0),
	IOC_DONE      = (1 <<  1),
};

/**
 * ioc_status_name() - printed representation of an enum &io_status
 * @st: an &io_status value
 *
 * Return: character string representing the status
 */
const char *ioc_status_name(int st);

/**
 * ioc_init() - initialize libioclient
 *
 * Call this before making any other calls to functions of this
 * library.
 *
 * Return: 0
 */
int ioc_init(void);

/**
 * ioc_create_context() - create a new context for libioc requests
 *
 * At least one context is necessary to submit iocbs.
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
 * @IOC_NOTIFY_CALLBACK: use a user-defined callback function
 * @IOC_NOTIFY_NONE:     Don't use notification.
 */
enum ioc_notify_type {
	IOC_NOTIFY_COMMON,
	IOC_NOTIFY_COND,
	IOC_NOTIFY_EVENTFD,
	IOC_NOTIFY_CALLBACK,
	IOC_NOTIFY_NONE,
};

/**
 * ioc_notify_calback - function prototype for event notification
 * @iocb: the iocb that had an event.
 *
 * Callback functions are called in the event thread's context and should
 * be minimal. In no event they should block.
 */
typedef void (*ioc_notify_callback) (struct iocb *iocb);

union ioc_notify_arg {
	ioc_notify_callback cb;
	int eventfd;
};

/**
 * ioc_new_iocb() - create an iocb object
 * @ctx: context in which to create the iocb
 * @type: enum &ioc_notify_type value, see above.
 * @arg: notify argument, for @IOC_NOTIFY_CALLBACK or @IOC_NOTIFY_EVENTFD
 * @free_resources: a function that will be called when the IO completes
 *
 * This function creates the basic unit for I/O in libioclient,  the iocb.
 * The data structure is the same as in libaio.
 * The libaio functions io_prep_pread() and io_prep_pwrite()
 * can be used to initialize &iocb objects for actual I/O.
 *
 * @arg.cb should contain the callback function if @type is
 * @IOC_NOTIFY_CALLBACK. If @type is @IOC_NOTIFY_EVENTFD, @arg.eventfd will
 * be set the eventfd upon successful return, if @arg is non-NULL.
 * For other values of @type, @arg is unused.
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
			  union ioc_notify_arg *arg,
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
 * The argument is defined as ``void *`` to make it possible to pass this
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
 * ioc_wait_done() first. ESHUTDOWN: ioc_put_context() has been called on the
 * iocb's context.
 */
int ioc_submit(struct iocb *iocb, uint64_t deadline);

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

/**
 * ioc_is_inflight() - check if IO is in flight for iocb
 * @iocb: the iocb to check.
 *
 * Return: ``true`` if I/O is in flight.
 */
bool ioc_is_inflight(const struct iocb *iocb);

/**
 * ioc_has_timed_out() - check if has timed out
 * @iocb: the iocb to check.
 *
 * Return: ``true`` if the deadline given in ioc_submit() had
 * expired before the IO completed.
 */
bool ioc_has_timed_out(const struct iocb *iocb);

/**
 * ioc_wait_event() - wait for completion or timeout
 * @iocb:    the iocb to wait on
 *
 * This function waits on an iocb until its status has either
 * completed or timed out.
 *
 * Return: See ioc_wait_done().
 */
int ioc_wait_event(struct iocb *iocb);

/**
 * ioc_wait_done() - wait until completion
 * @iocb:    the iocb to wait on
 * @st:	     pointer for io_status
 *
 * This function waits until I/O in flight completes. If it returns
 * success, ioc_is_inflight() is guaranteed to return ``false``.
 *
 * Return: 0 in case of success. -1 in case of failure.
 *         Error code: -EINVAL: called for notification type &IOC_NOTIFY_NONE or
 *         %IOC_NOTIFY_CALLBACK.
 *         For IOC_NOTIFY_EVENTFD, other errno values as set by read()
 *         and poll() are possible.
 */
int ioc_wait_done(struct iocb *iocb);

#endif /* _IOC_H */
