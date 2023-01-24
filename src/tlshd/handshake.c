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

static char tlshd_peername[NI_MAXHOST] = "unknown";
static struct sockaddr_storage tlshd_peeraddr;
static socklen_t tlshd_peeraddr_len;

int tlshd_completion_status;

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
		gnutls_global_deinit();
		return;
	}
	switch (type) {
	case TLSH_TYPE_CLIENTHELLO_ANON:
		tlshd_client_anon_handshake(sock, tlshd_peername);
		break;
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
