# libioclient - a simple aio wrapper library

**This is work in progress**, not in usable state yet.

Reviews and comments are welcome nonetheless.

## Introduction ##

This library provides wrappers for `libaio` calls. The emphasis is on
event notification. `libioclient` users don't have to parse `io_getevents`
return values, they get notifications for I/O completion via `pthreads` 
condition variables or `eventfd` mechanism. Another important aspect
is *timeout notification*. The user doesn't have to bother with aio
context allocation, `libioclient` automates this, increasing the size
of the aio context if necessary.

See the API documentation in [ioc.h](include/ioc.h).

## libscsi-debug - a library for using the Linux scsi-debug driver from C

The main intended purpose of this library is to ease testing of libioclient.
It is still work in progress and far from being usable though.

See the API documentation in [scsi-debug.h](include/scsi-debug.h).

# LICENSE

The libraries are released under the GNU Library General Public License
(LGPL), version 2.1 or newer (see [COPYING](COPYING)).
The unit test code is released under the GNU General Public License (GPL),
verson 2.0 or newer (see [COPYING.tests](COPYING.tests)).



