/*
 * Copyright (c) 2020 Martin Wilck, SUSE Software Solutions Germany GmbH
 * SPDX-license-identifier: LGPL-2.0-or-later
 */

#ifndef _IOCTEST_SCSI_H
#define _IOCTEST_SCSI_H
#include <stdbool.h>

#define SDBG_MOD_NAME "scsi_debug"

/**
 * is_module_loaded() - check if a module is loaded
 * @name: name of module to query
 *
 * Return: 1 if scsi_debug is loaded, 0 otherwise, -1 on error
 */
int is_module_loaded(const char *name);

/**
 * load_module() - load a kernel module and its dependencies
 * @name: name of module to load
 *
 * This is like "modprobe", but without support for module options
 * and other advanced flags.
 *
 * Return: 0 if successful, -1 otherwise.
 */
int load_module(const char *name);

/**
 * load_module() - load a kernel module
 * @name: name of module to unload
 *
 * Return: 0 if successful, -1 otherwise.
 */
int unload_module(const char *name);

/**
 * sdbg_release() - release resources
 *
 * Call to release resources if no further calls to functions from this
 * header file are planned in the near future. If this is not called,
 * it will be called automatically at program exit using atexit(3).
 * It is ok to call other functions after sdbg_release(), but it will
 * cause a re-initialization of libkmod, and thus cost some resources.
 */
void sdbg_release(void);

#endif /* _IOCTEST_SCSI_H */
