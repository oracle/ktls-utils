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
 *
 * For the moment, tlshd handles only client-side sockets.
 */
void tlshd_service_socket(void)
{
	struct tlshd_handshake_parms parms;
	int ret;

	tlshd_completion_status = -EIO;
	atexit(tlshd_handshake_complete);

	if (tlshd_nl_get_handshake_parms(&parms) < 0)
		return;

	memset(&tlshd_peeraddr, 0, sizeof(tlshd_peeraddr));
	tlshd_peeraddr_len = sizeof(tlshd_peeraddr);
	if (getpeername(parms.sockfd, (struct sockaddr *)&tlshd_peeraddr,
			&tlshd_peeraddr_len) == -1) {
		tlshd_log_perror("getpeername");
		goto out;
	}

	ret = getnameinfo((struct sockaddr *)&tlshd_peeraddr, tlshd_peeraddr_len,
			  tlshd_peername, sizeof(tlshd_peername), NULL, 0,
			  NI_NAMEREQD);
	if (ret) {
		tlshd_log_gai_error(ret);
		goto out;
	}
	parms.peername = tlshd_peername;

	tlshd_tls13_handler(&parms);

out:
	free(parms.priorities);

	tlshd_nl_done(&parms);
}
