/* SPDX-License-Identifier: LGPL-2.1 WITH Linux-syscall-note */
#ifndef AF_TSA_KERNEL_H
#define AF_TSA_KERNEL_H

#include <linux/types.h>
#include <linux/socket.h>

/* Commands sent from userspace */
enum {
	TSA_C_CREATE,
	TSA_C_SWAP,
	__TASKINTROSPECTION_C_MAX,
};
#define TSA_C_MAX (__TSA_C_MAX - 1)

/* Attributes for the create command */
enum {
	TSA_C_CREATE_A_UNSPEC = 0,
	TSA_C_CREATE_A_DOMAIN,
	TSA_C_CREATE_A_TYPE,
	TSA_C_CREATE_A_PROTOCOL,
	TSA_C_CREATE_A_FLAGS,
	__TSA_C_CREATE_A_MAX,
};
#define TSA_C_CREATE_A_MAX                                   \
	(__TSA_C_CREATE_A_MAX - 1)

/* Attributes for the swap command */
enum {
	TSA_C_SWAP_A_UNSPEC = 0,
	TSA_C_SWAP_A_FD,
	__TSA_C_SWAP_A_MAX,
};
#define TSA_C_SWAP_A_MAX                                   \
	(__TSA_C_SWAP_A_MAX - 1)

#define TSA_C_CREATE_A_FAMILY TSA_C_CREATE_A_DOMAIN

/* Potential return attributes */
enum {
	TSA_A_UNSPEC = 0,
	TSA_A_FD,
	__TSA_A_MAX,
};
#define TSA_A_MAX (__TSA_A_MAX - 1)

#define TSA_GENL_NAME "tsa"
#define TSA_GENL_VERSION 1

#endif