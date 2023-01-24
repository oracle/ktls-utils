/*
 * Perform a TLSv1.3 handshake.
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
#include <stdio.h>
#include <errno.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <linux/tls.h>

#include <glib.h>

#include "tlshd.h"

static void tlshd_start_tls_handshake(gnutls_session_t session)
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
 * tlshd_client_anon_handshake - encryption-only TLS session
 * @sock: Connected socket on which to perform the handshake
 * @peername: remote's domain name (NUL-terminated)
 *
 */
void tlshd_client_anon_handshake(int sock, const char *peername)
{
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	unsigned int flags;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	/*
	 * Don't reject self-signed server certificates.
	 */
	gnutls_certificate_set_verify_flags(xcred,
			GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 | GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5);
	gnutls_certificate_set_flags(xcred,
			GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH | GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK);

	ret = gnutls_certificate_set_x509_system_trust(xcred);
	if (ret < 0) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	tlshd_log_debug("System trust: Loaded %d certificate(s).", ret);

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

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = gnutls_set_default_priority(session);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	gnutls_session_set_verify_cert(session, peername, 0);

	tlshd_start_tls_handshake(session);

	gnutls_deinit(session);

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

static gnutls_privkey_t tlshd_privkey;
static gnutls_pcert_st tlshd_cert;

/*
 * XXX: After this point, tlshd_cert should be deinited on error.
 */
static bool tlshd_x509_client_get_cert(int sock)
{
	key_serial_t cert;
	socklen_t optlen;

	optlen = sizeof(cert);
	if (getsockopt(sock, SOL_TLSH, TLSH_X509_CERTIFICATE, &cert, &optlen) == -1) {
		tlshd_log_perror("Failed to fetch TLS x.509 certificate");
		return false;
	}
	if (cert != TLSH_NO_CERT)
		return tlshd_keyring_get_cert(cert, &tlshd_cert);
	return tlshd_config_get_client_cert(&tlshd_cert);
}

/*
 * XXX: After this point, tlshd_privkey should be deinited on error.
 */
static bool tlshd_x509_client_get_privkey(int sock)
{
	key_serial_t privkey;
	socklen_t optlen;

	optlen = sizeof(privkey);
	if (getsockopt(sock, SOL_TLSH, TLSH_X509_PRIVKEY, &privkey, &optlen) == -1) {
		tlshd_log_perror("Failed to fetch TLS x.509 private key");
		return false;
	}
	if (privkey != TLSH_NO_KEY)
		return tlshd_keyring_get_privkey(privkey, tlshd_privkey);
	return tlshd_config_get_client_privkey(&tlshd_privkey);
}

static void tlshd_x509_log_issuers(const gnutls_datum_t *req_ca_rdn, int nreqs)
{
	char issuer_dn[256];
	size_t len;
	int i, ret;

	if (nreqs < 1)
		return;

	tlshd_log_debug("Server's trusted authorities:");

	for (i = 0; i < nreqs; i++) {
		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
		if (ret >= 0)
			tlshd_log_debug("   [%d]: %s", i, issuer_dn);
	}
}

/**
 * tlshd_x509_retrieve_key_cb - Initialize client's x.509 identity
 *
 * Callback function is of type gnutls_certificate_retrieve_function2
 *
 * Initial implementation based on the cert_callback() function in
 * gnutls/doc/examples/ex-cert-select.c.
 *
 * Sketched-in and untested.
 *
 * Return values:
 *   %0: Success; output parameters are set accordingly
 *   %-1: Failure
 */
static int
tlshd_x509_retrieve_key_cb(gnutls_session_t session,
			   const gnutls_datum_t *req_ca_rdn, int nreqs,
			   __attribute__ ((unused)) const gnutls_pk_algorithm_t *pk_algos,
			   __attribute__ ((unused)) int pk_algos_length,
			   gnutls_pcert_st **pcert,
			   unsigned int *pcert_length,
			   gnutls_privkey_t *privkey)
{
	gnutls_certificate_type_t type;

	tlshd_x509_log_issuers(req_ca_rdn, nreqs);

	type = gnutls_certificate_type_get(session);
	if (type != GNUTLS_CRT_X509)
		return -1;

	*pcert_length = 1;
	*pcert = &tlshd_cert;
	*privkey = tlshd_privkey;
	return 0;
}

/**
 * tlshd_client_x509_handshake - authenticated x.509 TLS session
 * @sock: Connected socket on which to perform the handshake
 * @peername: remote's domain name (NUL-terminated)
 *
 */
void tlshd_client_x509_handshake(int sock, const char *peername)
{
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	unsigned int flags;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	ret = gnutls_certificate_set_x509_system_trust(xcred);
	if (ret < 0) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	tlshd_log_debug("System trust: Loaded %d certificate(s).", ret);

	if (!tlshd_x509_client_get_cert(sock))
		goto out_free_creds;
	if (!tlshd_x509_client_get_privkey(sock))
		goto out_free_creds;
	gnutls_certificate_set_retrieve_function2(xcred,
						  tlshd_x509_retrieve_key_cb);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_session_set_verify_cert(session, peername, 0);

	tlshd_start_tls_handshake(session);

	gnutls_deinit(session);

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

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

	tlshd_start_tls_handshake(session);

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_client_credentials(psk_cred);
}
