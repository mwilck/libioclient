# libioclient - a simple aio wrapper library

This library provides wrappers for `libaio` calls. The emphasis is on
*event notification*. `libioclient` users don't have to parse `io_getevents`
return values, they get notifications for I/O completion via `pthreads` 
condition variables or `eventfd` mechanism. Another important aspect
is *timeout notification*. The user doesn't have to bother with aio
context allocation, `libioclient` automates this, increasing the size
of the aio context if necessary.

See the API documentation in [ioc.h](include/ioc.h).
