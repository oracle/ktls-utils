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

static void tlshd_start_tls_handshake(gnutls_session_t session,
				      struct tlshd_handshake_parms *parms)
{
	char *desc;
	int ret;

	if (parms->priorities) {
		const char *err_pos;

		tlshd_log_debug("Using TLS priorities string %s\n",
				parms->priorities);
		ret = gnutls_priority_set_direct(session, parms->priorities,
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

	gnutls_handshake_set_timeout(session, parms->timeout);
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
		tlshd_completion_status = -EACCES;
		return;
	}

	desc = gnutls_session_get_desc(session);
	tlshd_log_debug("Session description: %s", desc);
	gnutls_free(desc);

	tlshd_completion_status = tlshd_initialize_ktls(session);
}

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

	tlshd_start_tls_handshake(session, parms);

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
	if (parms->x509_cert != HANDSHAKE_NO_CERT)
		return tlshd_keyring_get_cert(parms->x509_cert, &tlshd_cert);
	return tlshd_config_get_client_cert(&tlshd_cert);
}

/*
 * XXX: After this point, tlshd_privkey should be deinited on error.
 */
static bool tlshd_x509_client_get_privkey(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_privkey != HANDSHAKE_NO_PRIVKEY)
		return tlshd_keyring_get_privkey(parms->x509_privkey,
						 tlshd_privkey);
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
	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, parms->sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       parms->peername, strlen(parms->peername));
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_session_set_verify_cert(session, parms->peername, 0);

	tlshd_start_tls_handshake(session, parms);

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
	int ret;

	tlshd_peerid = parms->peerid;

	ret = gnutls_psk_allocate_client_credentials(&psk_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	gnutls_psk_set_client_credentials_function(psk_cred,
						   tlshd_psk_retrieve_key_cb);
	flags = GNUTLS_CLIENT;
	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, parms->sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       parms->peername, strlen(parms->peername));
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, psk_cred);

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_client_credentials(psk_cred);
}

/*
 * XXX: After this point, tlshd_cert should be deinited on error.
 */
static bool tlshd_x509_server_get_cert(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_cert != HANDSHAKE_NO_CERT)
		return tlshd_keyring_get_cert(parms->x509_cert, &tlshd_cert);
	return tlshd_config_get_server_cert(&tlshd_cert);
}

/*
 * XXX: After this point, tlshd_privkey should be deinited on error.
 */
static bool tlshd_x509_server_get_privkey(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_privkey != HANDSHAKE_NO_PRIVKEY)
		return tlshd_keyring_get_privkey(parms->x509_privkey,
						 tlshd_privkey);
	return tlshd_config_get_server_privkey(&tlshd_privkey);
}

static int tlshd_certificate_verify_function(gnutls_session_t session)
{
	const char *hostname;
	unsigned int status;
	gnutls_datum_t out;
	int type, ret;

	hostname = gnutls_session_get_ptr(session);

	ret = gnutls_certificate_verify_peers3(session, hostname, &status);
	switch (ret) {
	case GNUTLS_E_SUCCESS:
		break;
	case GNUTLS_E_NO_CERTIFICATE_FOUND:
		tlshd_log_debug("The peer presented no certificate.\n");
		return 0;
	default:
		tlshd_log_gnutls_error(ret);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

        type = gnutls_certificate_type_get(session);
        gnutls_certificate_verification_status_print(status, type, &out, 0);
        tlshd_log_debug("%s", out.data);
        gnutls_free(out.data);

        if (status)
                return GNUTLS_E_CERTIFICATE_ERROR;

	/* We might also examine extended key usage information here, if we want
	 * to get picky. Kernel would have to tell us what to look for. */

	/* XXX: Mark the peer authenticated. Netlink? */
	return 0;
}

static void tlshd_server_handshake(struct tlshd_handshake_parms *parms)
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

	if (!tlshd_x509_server_get_cert(parms))
		goto out_free_creds;
	if (!tlshd_x509_server_get_privkey(parms))
		goto out_free_creds;
	gnutls_certificate_set_retrieve_function2(xcred,
						  tlshd_x509_retrieve_key_cb);

	ret = gnutls_init(&session, GNUTLS_SERVER);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, parms->sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS,
			       parms->peername, strlen(parms->peername));
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_set_verify_function(xcred, tlshd_certificate_verify_function);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

/**
 * tlshd_tls13_handler - process a TLS v1.3 handshake request
 * @parms: requested handshake parameters
 *
 */
void tlshd_tls13_handler(struct tlshd_handshake_parms *parms)
{
	int ret;

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

	switch (parms->handshake_type) {
	case HANDSHAKE_NL_TLS_TYPE_CLIENTHELLO:
		switch (parms->auth_type) {
		case HANDSHAKE_NL_TLS_AUTH_UNAUTH:
			tlshd_client_anon_handshake(parms);
			break;
		case HANDSHAKE_NL_TLS_AUTH_X509:
			tlshd_client_x509_handshake(parms);
			break;
		case HANDSHAKE_NL_TLS_AUTH_PSK:
			tlshd_client_psk_handshake(parms);
			break;
		default:
			tlshd_log_debug("Unrecognized auth type (%d)",
					parms->auth_type);
		}
		break;
	case HANDSHAKE_NL_TLS_TYPE_SERVERHELLO:
		tlshd_server_handshake(parms);
		break;
	default:
		tlshd_log_debug("Unrecognized handshake type (%d)",
				parms->handshake_type);
	}

	gnutls_global_deinit();
}
