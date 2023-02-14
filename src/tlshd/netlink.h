/*
 * GENL HANDSHAKE service.
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * ktls-utils is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * Data structures and functions that are visible to user space are
 * declared here. This file constitutes an API contract between the
 * Linux kernel and user space.
 */

#ifndef _UAPI_LINUX_HANDSHAKE_H
#define _UAPI_LINUX_HANDSHAKE_H

#define HANDSHAKE_GENL_NAME	"handshake"
#define HANDSHAKE_GENL_VERSION	0x01

enum handshake_genl_mcgrps {
	HANDSHAKE_GENL_MCGRP_NONE = 0,
	HANDSHAKE_GENL_MCGRP_TLS,
};

#define HANDSHAKE_GENL_MCGRP_NONE_NAME	"none"
#define HANDSHAKE_GENL_MCGRP_TLS_NAME	"tls"

enum handshake_genl_cmds {
	HANDSHAKE_GENL_CMD_UNSPEC = 0,
	HANDSHAKE_GENL_CMD_READY,
	HANDSHAKE_GENL_CMD_ACCEPT,
	HANDSHAKE_GENL_CMD_DONE,

	__HANDSHAKE_GENL_CMD_MAX
};
#define HANDSHAKE_GENL_CMD_MAX	(__HANDSHAKE_GENL_CMD_MAX - 1)

enum handshake_genl_attrs {
	HANDSHAKE_GENL_ATTR_UNSPEC = 0,
	HANDSHAKE_GENL_ATTR_MSG_STATUS,
	HANDSHAKE_GENL_ATTR_SESS_STATUS,
	HANDSHAKE_GENL_ATTR_SOCKFD,
	HANDSHAKE_GENL_ATTR_PROTOCOL,

	HANDSHAKE_GENL_ATTR_ACCEPT,
	HANDSHAKE_GENL_ATTR_DONE,

	__HANDSHAKE_GENL_ATTR_MAX
};
#define HANDSHAKE_GENL_ATTR_MAX	(__HANDSHAKE_GENL_ATTR_MAX - 1)


/*
 * Items specific to TLSv1.3 handshakes
 */

enum handshake_tls_accept_attrs {
	HANDSHAKE_GENL_ATTR_TLS_ACCEPT_UNSPEC = 0,
	HANDSHAKE_GENL_ATTR_TLS_TYPE,
	HANDSHAKE_GENL_ATTR_TLS_AUTH,
	HANDSHAKE_GENL_ATTR_TLS_PRIORITIES,
	HANDSHAKE_GENL_ATTR_TLS_X509_CERT,
	HANDSHAKE_GENL_ATTR_TLS_X509_PRIVKEY,
	HANDSHAKE_GENL_ATTR_TLS_PSK,
	HANDSHAKE_GENL_ATTR_TLS_TIMEOUT,
	HANDSHAKE_GENL_ATTR_TLS_KEYRING,

	__HANDSHAKE_GENL_ATTR_TLS_ACCEPT_MAX
};
#define HANDSHAKE_GENL_ATTR_TLS_ACCEPT_MAX \
	(__HANDSHAKE_GENL_ATTR_TLS_ACCEPT_MAX - 1)

enum handshake_tls_done_attrs {
	HANDSHAKE_GENL_ATTR_TLS_DONE_UNSPEC = 0,
	HANDSHAKE_GENL_ATTR_TLS_REMOTE_PEERID,

	__HANDSHAKE_GENL_ATTR_TLS_DONE_MAX
};
#define HANDSHAKE_GENL_ATTR_TLS_DONE_MAX \
	(__HANDSHAKE_GENL_ATTR_TLS_DONE_MAX - 1)

enum handshake_genl_protocol {
	HANDSHAKE_GENL_PROTO_UNSPEC = 0,
	HANDSHAKE_GENL_PROTO_TLS,
};

enum handshake_genl_tls_type {
	HANDSHAKE_GENL_TLS_TYPE_UNSPEC = 0,
	HANDSHAKE_GENL_TLS_TYPE_CLIENTHELLO,
	HANDSHAKE_GENL_TLS_TYPE_SERVERHELLO,
};

enum handshake_genl_tls_auth {
	HANDSHAKE_GENL_TLS_AUTH_UNSPEC = 0,
	HANDSHAKE_GENL_TLS_AUTH_UNAUTH,
	HANDSHAKE_GENL_TLS_AUTH_X509,
	HANDSHAKE_GENL_TLS_AUTH_PSK,
};

#endif /* _UAPI_LINUX_HANDSHAKE_H */
