/*
 * Copyright (c) 2020 Martin Wilck, SUSE Software Solutions Germany GmbH
 * SPDX-license-identifier: LGPL-2.0-or-later
 */

#ifndef _IOCTEST_SCSI_H
#define _IOCTEST_SCSI_H
#include <stdbool.h>

#define SDBG_MOD_NAME "scsi_debug"

/**
 * sdbg_is_module_loaded() - check if a module is loaded
 * @name: name of module to query
 *
 * Test the initstate of the kernel module with the given name.
 * @name must be an actual module name, not an alias.
 *
 * Return: 1 if module is loaded, 0 otherwise, -1 on error, setting errno
 */
int sdbg_is_module_loaded(const char *name);

/**
 * sdbg_load_module() - load a kernel module and its dependencies
 * @name: name of module to load
 *
 * This works like "modprobe". "install" statements and softdeps
 * in modprobe.d are ignored for security reasons.
 *
 * Return: 0 if successful or if module is already loaded,
 * -1 otherwise, setting errno.
 */
int sdbg_load_module(const char *name);

/**
 * sdbg_unload_module() - unload a kernel module
 * @name: name of module to unload
 *
 * Return: 0 if successful or if module isn't loaded, -1 otherwise.
 */
int sdbg_unload_module(const char *name);

/**
 * sdbg_module_release() - release resources
 *
 * Call to release resources if no further calls to functions from this
 * header file are planned in the near future. If this is not called,
 * it will be called automatically at program exit using atexit(3).
 * It is ok to call other module handling functions after sdbg_release(),
 * but it will cause a re-initialization of libkmod, and thus cost some
 * resources.
 */
void sdbg_module_release(void);

#endif /* _IOCTEST_SCSI_H */
