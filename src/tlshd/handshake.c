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

#include "tlshd.h"

static char tlshd_peername[NI_MAXHOST];
static struct sockaddr_storage tlshd_peeraddr;
static socklen_t tlshd_peeraddr_len;

static int tlshd_completion_status;

/*
 * Notify the kernel that the user space handshake process has completed
 * and the socket is ready to be used or that the handshake failed.
 */
static void tlshd_handshake_complete(void)
{
	if (tlshd_completion_status) {
		tlshd_log_failure(tlshd_peername,
				  (struct sockaddr *)&tlshd_peeraddr, tlshd_peeraddr_len);
		return;
	}

	tlshd_log_success(tlshd_peername,
			  (struct sockaddr *)&tlshd_peeraddr, tlshd_peeraddr_len);
}

/**
 * tlshd_client_handshake - Drive the handshake interaction
 * @session: TLS session to initialize
 *
 */
void tlshd_client_handshake(gnutls_session_t session)
{
	char priorities[2048];
	socklen_t optlen;
	char *desc;
	int ret;

	optlen = sizeof(priorities);
	memset(priorities, 0, optlen);
	if (getsockopt(gnutls_transport_get_int(session),
		       SOL_TLSH, TLSH_PRIORITIES, priorities, &optlen) == -1)
		tlshd_log_perror("Failed to fetch TLS priority string");
	if (strlen(priorities)) {
		const char *err_pos;

		tlshd_log_debug("Using TLS priorities string %s\n", priorities);
		ret = gnutls_priority_set_direct(session, priorities,
						 &err_pos);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_gnutls_error(ret);
			return;
		}
	} else {
		tlshd_log_debug("Using default TLS priorities\n");
		ret = gnutls_set_default_priority(session);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_gnutls_error(ret);
			return;
		}
	}

	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
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
		return;
	}

	desc = gnutls_session_get_desc(session);
	tlshd_log_debug("Session description: %s", desc);
	gnutls_free(desc);

	tlshd_completion_status = tlshd_initialize_ktls(session);
}

/**
 * tlshd_service_socket - Service a kernel socket needing a key operation
 * @sock: socket descriptor of kernel socket to service
 *
 * This function notifies the kernel when the library has finished.
 *
 * For the moment, tlshd handles only client-side sockets.
 */
void tlshd_service_socket(int sock)
{
	socklen_t optlen;
	int type, ret;

	tlshd_completion_status = -EACCES;
	atexit(tlshd_handshake_complete);

	memset(&tlshd_peeraddr, 0, sizeof(tlshd_peeraddr));
	tlshd_peeraddr_len = sizeof(tlshd_peeraddr);
	if (getpeername(sock, (struct sockaddr *)&tlshd_peeraddr,
			&tlshd_peeraddr_len) == -1) {
		tlshd_log_perror("getpeername");
		return;
	}

	ret = getnameinfo((struct sockaddr *)&tlshd_peeraddr, tlshd_peeraddr_len,
			  tlshd_peername, sizeof(tlshd_peername), NULL, 0,
			  NI_NAMEREQD);
	if (ret) {
		tlshd_log_gai_error(ret);
		return;
	}

	ret = gnutls_global_init();
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	if (tlshd_library_debug)
		gnutls_global_set_log_level(tlshd_library_debug);
	gnutls_global_set_log_function(tlshd_gnutls_log_func);
	gnutls_global_set_audit_log_function(tlshd_gnutls_audit_func);

	tlshd_log_debug("System config file: %s", gnutls_get_system_config_file());

#if defined(HAVE_GNUTLS_PROTOCOL_SET_ENABLED)
	/*
	 * Both NVMe-TLS and RPC-with-TLS require the use of TLSv1.3.
	 * However, some current prototype implementations are limited
	 * to TLSv1.2 because not all OSes have support for TLSv1.3 yet.
	 *
	 * For security reasons, this min version must be set to NO LOWER
	 * THAN TLSv1.2. This setting must be increased to v1.3 when tlshd
	 * matriculates to product quality.
	 */
	gnutls_protocol_set_enabled(GNUTLS_SSL3,   0);
	gnutls_protocol_set_enabled(GNUTLS_TLS1_0, 0);
	gnutls_protocol_set_enabled(GNUTLS_TLS1_1, 0);
	gnutls_protocol_set_enabled(GNUTLS_TLS1_2, 1);
	gnutls_protocol_set_enabled(GNUTLS_TLS1_3, 1);
#endif /* HAVE_GNUTLS_PROTOCOL_SET_ENABLED */

	optlen = sizeof(type);
	if (getsockopt(sock, SOL_TLSH, TLSH_HANDSHAKE_TYPE, &type,
		       &optlen) == -1) {
		tlshd_log_perror("Failed to fetch TLS handshake type");
		type = TLSH_TYPE_CLIENTHELLO_X509;
	}
	switch (type) {
	case TLSH_TYPE_CLIENTHELLO_X509:
		tlshd_client_x509_handshake(sock, tlshd_peername);
		break;
	case TLSH_TYPE_CLIENTHELLO_PSK:
		tlshd_client_psk_handshake(sock, tlshd_peername);
		break;
	default:
		tlshd_log_debug("Unrecognized handshake type (%d)", type);
	}

	gnutls_global_deinit();
}
