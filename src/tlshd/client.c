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

static void tlshd_client_anon_handshake(struct tlshd_handshake_parms *parms)
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
	gnutls_transport_set_int(session, parms->sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       parms->peername, strlen(parms->peername));

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = gnutls_set_default_priority(session);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	gnutls_session_set_verify_cert(session, parms->peername, 0);

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
static bool tlshd_x509_client_get_cert(struct tlshd_handshake_parms *parms)
{
	key_serial_t cert;
	socklen_t optlen;

	optlen = sizeof(cert);
	if (getsockopt(parms->sockfd, SOL_TLSH, TLSH_X509_CERTIFICATE,
		       &cert, &optlen) == -1) {
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
static bool tlshd_x509_client_get_privkey(struct tlshd_handshake_parms *parms)
{
	key_serial_t privkey;
	socklen_t optlen;

	optlen = sizeof(privkey);
	if (getsockopt(parms->sockfd, SOL_TLSH, TLSH_X509_PRIVKEY,
		       &privkey, &optlen) == -1) {
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
 * tlshd_client_x509_verify_function - Verify remote's x.509 certificate
 * @session: session in the midst of a handshake
 *
 * Return values:
 *   %GNUTLS_E_SUCCESS: Incoming certificate has been successfully verified
 *   %GNUTLS_E_CERTIFICATE_ERROR: certificate verification failed
 */
static int tlshd_client_x509_verify_function(gnutls_session_t session)
{
	const char *hostname;
	unsigned int status;
	gnutls_datum_t out;
	int type, ret;

	hostname = gnutls_session_get_ptr(session);

	ret = gnutls_certificate_verify_peers3(session, hostname, &status);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

        type = gnutls_certificate_type_get(session);
        gnutls_certificate_verification_status_print(status, type, &out, 0);
        tlshd_log_debug("%s", out.data);
        gnutls_free(out.data);

        if (status)
                return GNUTLS_E_CERTIFICATE_ERROR;

	/* To do: Examine extended key usage information here, if we want
	 * to get picky. Kernel would have to tell us what to look for
	 * via a netlink attribute. */

	return GNUTLS_E_SUCCESS;
}

static void tlshd_client_x509_handshake(struct tlshd_handshake_parms *parms)
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

	if (!tlshd_x509_client_get_cert(parms))
		goto out_free_creds;
	if (!tlshd_x509_client_get_privkey(parms))
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
	gnutls_transport_set_int(session, parms->sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       parms->peername, strlen(parms->peername));
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_set_verify_function(xcred,
					       tlshd_client_x509_verify_function);
	gnutls_session_set_verify_cert(session, parms->peername, 0);

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

static void tlshd_client_psk_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_psk_client_credentials_t psk_cred;
	gnutls_session_t session;
	unsigned int flags;
	socklen_t optlen;
	int ret;

	optlen = sizeof(tlshd_peerid);
	if (getsockopt(parms->sockfd, SOL_TLSH, TLSH_PEERID, &tlshd_peerid,
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
	gnutls_transport_set_int(session, parms->sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       parms->peername, strlen(parms->peername));
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, psk_cred);

	tlshd_start_tls_handshake(session);

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_client_credentials(psk_cred);
}

/**
 * tlshd_clienthello_handshake - send a TLSv1.3 ClientHello
 * @parms: handshake parameters
 *
 */
void tlshd_clienthello_handshake(struct tlshd_handshake_parms *parms)
{
	socklen_t optlen;
	int type, ret;

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
	if (getsockopt(parms->sockfd, SOL_TLSH, TLSH_HANDSHAKE_TYPE, &type,
		       &optlen) == -1) {
		tlshd_log_perror("Failed to fetch TLS handshake type");
		gnutls_global_deinit();
		return;
	}
	switch (type) {
	case TLSH_TYPE_CLIENTHELLO_ANON:
		tlshd_client_anon_handshake(parms);
		break;
	case TLSH_TYPE_CLIENTHELLO_X509:
		tlshd_client_x509_handshake(parms);
		break;
	case TLSH_TYPE_CLIENTHELLO_PSK:
		tlshd_client_psk_handshake(parms);
		break;
	default:
		tlshd_log_debug("Unrecognized handshake type (%d)", type);
	}

	gnutls_global_deinit();
}
