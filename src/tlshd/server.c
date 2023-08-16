/*
 * Perform a TLSv1.3 server-side handshake.
 *
 * Copyright (c) 2023 Oracle and/or its affiliates.
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
#include "netlink.h"

static gnutls_privkey_t tlshd_server_privkey;
static gnutls_pcert_st tlshd_server_cert;

/*
 * XXX: After this point, tlshd_server_cert should be deinited on error.
 */
static bool tlshd_x509_server_get_cert(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_cert != TLS_NO_CERT)
		return tlshd_keyring_get_cert(parms->x509_cert, &tlshd_server_cert);
	return tlshd_config_get_server_cert(&tlshd_server_cert);
}

/*
 * XXX: After this point, tlshd_server_privkey should be deinited on error.
 */
static bool tlshd_x509_server_get_privkey(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_privkey != TLS_NO_PRIVKEY)
		return tlshd_keyring_get_privkey(parms->x509_privkey,
						 tlshd_server_privkey);
	return tlshd_config_get_server_privkey(&tlshd_server_privkey);
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
	*pcert = &tlshd_server_cert;
	*privkey = tlshd_server_privkey;
	return 0;
}

/**
 * tlshd_server_x509_verify_function - Verify remote's x.509 certificate
 * @session: session in the midst of a handshake
 *
 * A return value of %GNUTLS_E_SUCCESS indicates that the TLS session
 * has been allowed to continue. tlshd either sets the peerid array if
 * the presented certificate has been successfully verified, or the
 * peerid array is left empty if no peer information was available to
 * perform verification. The kernel consumer can apply a security policy
 * based on this information.
 *
 * A return value of %GNUTLS_E_CERTIFICATE_ERROR means that certificate
 * verification failed. The server sends an ALERT to the client.
 */
static int tlshd_server_x509_verify_function(gnutls_session_t session)
{
	struct tlshd_handshake_parms *parms;
	const gnutls_datum_t *peercerts;
	gnutls_certificate_type_t type;
	unsigned int i, status;
	gnutls_datum_t out;
	int ret;

	parms = gnutls_session_get_ptr(session);

	ret = gnutls_certificate_verify_peers3(session, NULL, &status);
	switch (ret) {
	case GNUTLS_E_SUCCESS:
		break;
	case GNUTLS_E_NO_CERTIFICATE_FOUND:
		tlshd_log_debug("The peer offered no certificate.");
		return GNUTLS_E_SUCCESS;
	default:
		tlshd_log_gnutls_error(ret);
		goto certificate_error;
	}
	type = gnutls_certificate_type_get(session);
	gnutls_certificate_verification_status_print(status, type, &out, 0);
	tlshd_log_debug("%s", out.data);
	gnutls_free(out.data);
	if (status)
		goto certificate_error;

	/* To do: Examine extended key usage information here, if we want
	 * to get picky. Kernel would have to tell us what to look for
	 * via a netlink attribute. */

	peercerts = gnutls_certificate_get_peers(session,
						 &parms->num_remote_peerids);
	if (!peercerts || parms->num_remote_peerids == 0) {
		tlshd_log_debug("The peer cert list is empty.");
		goto certificate_error;
	}

	tlshd_log_debug("The peer offered %u certificate(s).",
			parms->num_remote_peerids);

	if (parms->num_remote_peerids > ARRAY_SIZE(parms->remote_peerid))
		parms->num_remote_peerids = ARRAY_SIZE(parms->remote_peerid);
	for (i = 0; i < parms->num_remote_peerids; i++) {
		gnutls_x509_crt_t cert;

		gnutls_x509_crt_init(&cert);
		gnutls_x509_crt_import(cert, &peercerts[i], GNUTLS_X509_FMT_DER);
		parms->remote_peerid[i] =
			tlshd_keyring_create_cert(cert, parms->peername);
		gnutls_x509_crt_deinit(cert);
	}

	return GNUTLS_E_SUCCESS;

certificate_error:
	gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_ACCESS_DENIED);
	return GNUTLS_E_CERTIFICATE_ERROR;
}

static void tlshd_server_x509_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
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

	if (!tlshd_x509_server_get_cert(parms)) {
		goto out_free_creds;
	}
	if (!tlshd_x509_server_get_privkey(parms)) {
		goto out_free_creds;
	}
	gnutls_certificate_set_retrieve_function2(xcred,
						  tlshd_x509_retrieve_key_cb);

	ret = gnutls_init(&session, GNUTLS_SERVER);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, parms->sockfd);
	gnutls_session_set_ptr(session, parms);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_set_verify_function(xcred,
					       tlshd_server_x509_verify_function);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

/**
 * tlshd_server_psk_cb - Validate remote's username
 * @session: session in the midst of a handshake
 * @username: remote's username
 * @key: PSK matching @username
 *
 * Searches for a key with description @username in the session
 * keyring, and stores the PSK data in @key if found.
 *
 * Return values:
 *   %0: Matching key has been stored in @key
 *   %-1: Error during lookup, @key is not updated
 */
static int tlshd_server_psk_cb(gnutls_session_t session,
			       const char *username, gnutls_datum_t *key)
{
	struct tlshd_handshake_parms *parms;
	key_serial_t psk;
	long ret;

	parms = gnutls_session_get_ptr(session);

	ret = keyctl_search(KEY_SPEC_SESSION_KEYRING, "psk", username, 0);
	if (ret < 0) {
		tlshd_log_error("failed to search key");
		return -1;
	}

	psk = (key_serial_t)ret;
	if (!tlshd_keyring_get_psk_key(psk, key)) {
		tlshd_log_error("failed to load key");
		return -1;
	}

	/* PSK uses the same identity for both client and server */
	parms->remote_peerid[0] = psk;
	parms->num_remote_peerids = 1;
	return 0;
}

static void tlshd_server_psk_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_psk_server_credentials_t psk_cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_psk_allocate_server_credentials(&psk_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	gnutls_psk_set_server_credentials_function(psk_cred,
						   tlshd_server_psk_cb);

	ret = gnutls_init(&session, GNUTLS_SERVER);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, parms->sockfd);
	gnutls_session_set_ptr(session, parms);

	gnutls_credentials_set(session, GNUTLS_CRD_PSK, psk_cred);

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_server_credentials(psk_cred);
}

/**
 * tlshd_serverhello_handshake - send a TLSv1.3 ServerHello
 * @parms: handshake parameters
 *
 */
void tlshd_serverhello_handshake(struct tlshd_handshake_parms *parms)
{
	int ret;

	ret = gnutls_global_init();
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	if (tlshd_tls_debug)
		gnutls_global_set_log_level(tlshd_tls_debug);
	gnutls_global_set_log_function(tlshd_gnutls_log_func);
	gnutls_global_set_audit_log_function(tlshd_gnutls_audit_func);

#ifdef HAVE_GNUTLS_GET_SYSTEM_CONFIG_FILE
	tlshd_log_debug("System config file: %s",
			gnutls_get_system_config_file());
#endif

	switch (parms->auth_mode) {
	case HANDSHAKE_AUTH_X509:
		tlshd_server_x509_handshake(parms);
		break;
	case HANDSHAKE_AUTH_PSK:
		tlshd_server_psk_handshake(parms);
		break;
	default:
		tlshd_log_debug("Unrecognized auth mode (%d)",
				parms->auth_mode);
	}

	gnutls_global_deinit();
}
