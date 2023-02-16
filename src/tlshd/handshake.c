/*
 * Service a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 *
 * Copyright (c) 2022 Oracle and/or its affiliates.
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

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/tcp.h>
#include <netdb.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>

#include "tlshd.h"
#include "netlink.h"

/**
 * tlshd_start_tls_handshake - Drive the handshake interaction
 * @session: TLS session to initialize
 *
 */
void tlshd_start_tls_handshake(gnutls_session_t session,
			       struct tlshd_handshake_parms *parms)
{
	char *desc;
	unsigned int timeout;
	int ret;

	if (parms->priorities) {
		const char *err_pos;

		tlshd_log_debug("Using TLS priorities string %s\n",
				parms->priorities);
		ret = gnutls_priority_set_direct(session, parms->priorities,
						 &err_pos);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_gnutls_error(ret);
			parms->session_status = -EINVAL;
			return;
		}
	} else {
		ret = gnutls_set_default_priority(session);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_gnutls_error(ret);
			parms->session_status = -EINVAL;
			return;
		}
	}

	if (parms->timeout == TLS_NO_TIMEOUT)
		timeout = GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;
	else
		timeout = parms->timeout * 1000;
	gnutls_handshake_set_timeout(session, timeout);
	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
	if (ret < 0) {
		switch (ret) {
		case GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR:
			tlshd_log_cert_verification_error(session);
			break;
		default:
			tlshd_log_gnutls_error(ret);
		}
		parms->session_status = -EACCES;
		return;
	}

	desc = gnutls_session_get_desc(session);
	tlshd_log_debug("Session description: %s", desc);
	gnutls_free(desc);

	parms->session_status = tlshd_initialize_ktls(session);
}

/**
 * tlshd_service_socket - Service a kernel socket needing a key operation
 *
 */
void tlshd_service_socket(void)
{
	static char peername[NI_MAXHOST] = "unknown";
	struct tlshd_handshake_parms parms = {
		.session_status	= -EIO,
	};
	static struct sockaddr_storage ss;
	static socklen_t peeraddr_len;
	struct sockaddr *peeraddr = (struct sockaddr *)&ss;
	int ret;

	if (tlshd_genl_get_handshake_parms(&parms) < 0)
		goto out;

	memset(&ss, 0, sizeof(ss));
	peeraddr_len = sizeof(ss);
	if (getpeername(parms.sockfd, peeraddr, &peeraddr_len) == -1) {
		tlshd_log_perror("getpeername");
		goto out;
	}

	ret = getnameinfo(peeraddr, peeraddr_len, peername, sizeof(peername),
			  NULL, 0, NI_NAMEREQD);
	if (ret) {
		tlshd_log_gai_error(ret);
		goto out;
	}
	parms.peername = peername;

	switch (parms.handshake_type) {
	case HANDSHAKE_GENL_TLS_TYPE_CLIENTHELLO:
		tlshd_clienthello_handshake(&parms);
		break;
	case HANDSHAKE_GENL_TLS_TYPE_SERVERHELLO:
		tlshd_serverhello_handshake(&parms);
		break;
	default:
		tlshd_log_debug("Unrecognized handshake type (%d)",
				parms.handshake_type);
	}

out:
	free(parms.priorities);

	tlshd_genl_done(&parms);
	if (parms.session_status)
		tlshd_log_failure(peername, peeraddr, peeraddr_len);
	else
		tlshd_log_success(peername, peeraddr, peeraddr_len);
}
