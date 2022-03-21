/*
 * Perform a TLS handshake using pre-shared keys.
 *
 * Copyright (c) 2022 Oracle and/or its affiliates.
 * Copyright (c) 2022 SUSE LLC.
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
#include <errno.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <linux/tls.h>

#include "tlshd.h"

static key_serial_t tlshd_peerid;

static int tlshd_psk_retrieve_key_cb(__attribute__ ((unused))gnutls_session_t session,
				     char **username, gnutls_datum_t *key)
{
	if (!tlshd_keyring_get_psk_username(tlshd_peerid, username))
		return -1;
	if (!tlshd_keyring_get_psk_key(tlshd_peerid, key))
		return -1;
	return 0;
}

/**
 * tlshd_client_psk_handshake - PSK-authenticated TLS session
 * @sock: Connected socket on which to perform the handshake
 * @peername: remote's domain name (NUL-terminated)
 *
 */
void tlshd_client_psk_handshake(int sock, const char *peername)
{
	gnutls_psk_client_credentials_t psk_cred;
	gnutls_session_t session;
	unsigned int flags;
	socklen_t optlen;
	int ret;

	optlen = sizeof(tlshd_peerid);
	if (getsockopt(sock, SOL_TLSH, TLSH_PEERID, &tlshd_peerid,
		       &optlen) == -1) {
		tlshd_log_perror("Failed to fetch TLS peer ID");
		return;
	}

	ret = gnutls_psk_allocate_client_credentials(&psk_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	gnutls_psk_set_client_credentials_function(psk_cred,
						   tlshd_psk_retrieve_key_cb);
	flags = GNUTLS_CLIENT;
#if defined(GNUTLS_NO_TICKETS)
	flags |= GNUTLS_NO_TICKETS;
#endif
	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, sock);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       peername, strlen(peername));
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, psk_cred);

	tlshd_client_handshake(session);

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_client_credentials(psk_cred);
}
