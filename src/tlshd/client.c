/*
 * Perform a TLSv1.3 handshake.
 *
 * Copyright (c) 2022 Oracle and/or its affiliates.
 * Copyright (c) 2022 SUSE LLC.
 * Copyright (c) 2024 Red Hat, Inc.
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

static void tlshd_tls13_client_anon_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	unsigned int flags;
	char *cafile;
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

	if (tlshd_config_get_client_truststore(&cafile)) {
		ret = gnutls_certificate_set_x509_trust_file(xcred, cafile,
							     GNUTLS_X509_FMT_PEM);
		free(cafile);
	} else
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
		goto out_free_creds;
	}

	ret = tlshd_gnutls_priority_set(session, parms, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}

	gnutls_session_set_verify_cert(session, parms->peername, 0);

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

static gnutls_privkey_t tlshd_privkey;
static unsigned int tlshd_certs_len = TLSHD_MAX_CERTS;
static gnutls_pcert_st tlshd_certs[TLSHD_MAX_CERTS];

/*
 * XXX: After this point, tlshd_certs should be deinited on error.
 */
static bool tlshd_x509_client_get_certs(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_cert != TLS_NO_CERT)
		return tlshd_keyring_get_certs(parms->x509_cert, tlshd_certs,
					       &tlshd_certs_len);
	return tlshd_config_get_client_certs(tlshd_certs, &tlshd_certs_len);
}

/*
 * XXX: After this point, tlshd_privkey should be deinited on error.
 */
static bool tlshd_x509_client_get_privkey(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_privkey != TLS_NO_PRIVKEY)
		return tlshd_keyring_get_privkey(parms->x509_privkey,
						 &tlshd_privkey);
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

	*pcert_length = tlshd_certs_len;
	*pcert = tlshd_certs;
	*privkey = tlshd_privkey;
	return 0;
}

/**
 * tlshd_client_x509_verify_function - Verify remote's x.509 certificate
 * @session: session in the midst of a handshake
 * @parms: handshake parameters
 *
 * Return values:
 *   %GNUTLS_E_SUCCESS: Incoming certificate has been successfully verified
 *   %GNUTLS_E_CERTIFICATE_ERROR: certificate verification failed
 */
static int tlshd_client_x509_verify_function(gnutls_session_t session,
					     struct tlshd_handshake_parms *parms)
{
	const gnutls_datum_t *peercerts;
	gnutls_certificate_type_t type;
	unsigned int i, status;
	gnutls_datum_t out;
	int ret;

	ret = gnutls_certificate_verify_peers3(session, parms->peername,
					       &status);
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

	peercerts = gnutls_certificate_get_peers(session,
						 &parms->num_remote_peerids);
	if (!peercerts || parms->num_remote_peerids == 0) {
		tlshd_log_debug("The peer cert list is empty.\n");
                return GNUTLS_E_CERTIFICATE_ERROR;
	}

	tlshd_log_debug("The peer offered %u certificate(s).\n",
			parms->num_remote_peerids);

	if (parms->num_remote_peerids > ARRAY_SIZE(parms->remote_peerid))
		parms->num_remote_peerids = ARRAY_SIZE(parms->remote_peerid);
	for (i = 0; i < parms->num_remote_peerids; i++) {
		gnutls_x509_crt_t cert;

		gnutls_x509_crt_init(&cert);
		ret = gnutls_x509_crt_import(cert, &peercerts[i],
					     GNUTLS_X509_FMT_DER);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_gnutls_error(ret);
			gnutls_x509_crt_deinit(cert);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		parms->remote_peerid[i] =
			tlshd_keyring_create_cert(cert, parms->peername);
		gnutls_x509_crt_deinit(cert);
	}

	return GNUTLS_E_SUCCESS;
}

static int tlshd_tls13_client_x509_verify_function(gnutls_session_t session)
{
	struct tlshd_handshake_parms *parms = gnutls_session_get_ptr(session);

	return tlshd_client_x509_verify_function(session, parms);
}

static void tlshd_tls13_client_x509_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	unsigned int flags;
	char *cafile;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}

	if (tlshd_config_get_client_truststore(&cafile)) {
		ret = gnutls_certificate_set_x509_trust_file(xcred, cafile,
							     GNUTLS_X509_FMT_PEM);
		free(cafile);
	} else
		ret = gnutls_certificate_set_x509_system_trust(xcred);
	if (ret < 0) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	tlshd_log_debug("System trust: Loaded %d certificate(s).", ret);

	if (!tlshd_x509_client_get_certs(parms))
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
	gnutls_session_set_ptr(session, parms);

	ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS,
				     parms->peername, strlen(parms->peername));
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	ret = tlshd_gnutls_priority_set(session, parms, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_certificate_set_verify_function(xcred,
					       tlshd_tls13_client_x509_verify_function);

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

static void tlshd_tls13_client_psk_handshake_one(struct tlshd_handshake_parms *parms,
						 key_serial_t peerid)
{
	gnutls_psk_client_credentials_t psk_cred;
	gnutls_session_t session;
	gnutls_datum_t key;
	unsigned int flags;
	char *identity;
	int ret;

	if (!tlshd_keyring_get_psk_username(peerid, &identity)) {
		tlshd_log_error("Failed to get key identity");
		return;
	}

	if (!tlshd_keyring_get_psk_key(peerid, &key)) {
		tlshd_log_error("Failed to read key");
		free(identity);
		return;
	}

	ret = gnutls_psk_allocate_client_credentials(&psk_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(identity);
		return;
	}

	ret = gnutls_psk_set_client_credentials(psk_cred, identity, &key,
						GNUTLS_PSK_KEY_RAW);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}

	flags = GNUTLS_CLIENT;
	ret = gnutls_init(&session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}
	gnutls_transport_set_int(session, parms->sockfd);
	gnutls_session_set_ptr(session, parms);
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, psk_cred);

	ret = tlshd_gnutls_priority_set(session, parms, key.size);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}

	tlshd_log_debug("start ClientHello handshake");
	tlshd_start_tls_handshake(session, parms);
	if (!parms->session_status) {
		/* PSK uses the same identity for both client and server */
		parms->num_remote_peerids = 1;
		parms->remote_peerid[0] = peerid;
	}

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_client_credentials(psk_cred);
	free(identity);
}

static void tlshd_tls13_client_psk_handshake(struct tlshd_handshake_parms *parms)
{
	unsigned int i;

	if (!parms->peerids) {
		tlshd_log_error("No key identities");
		return;
	}

	/*
	 * GnuTLS does not yet support multiple offered PskIdentities.
	 * Retry ClientHello with each identity on the kernel's list.
	 */
	for (i = 0; i < parms->num_peerids; i++) {
		tlshd_tls13_client_psk_handshake_one(parms, parms->peerids[i]);
		if (parms->session_status != EACCES)
			break;
	}
}

/**
 * tlshd_tls13_clienthello_handshake - send a TLSv1.3 ClientHello
 * @parms: handshake parameters
 *
 */
void tlshd_tls13_clienthello_handshake(struct tlshd_handshake_parms *parms)
{
	switch (parms->auth_mode) {
	case HANDSHAKE_AUTH_UNAUTH:
		tlshd_tls13_client_anon_handshake(parms);
		break;
	case HANDSHAKE_AUTH_X509:
		tlshd_tls13_client_x509_handshake(parms);
		break;
	case HANDSHAKE_AUTH_PSK:
		tlshd_tls13_client_psk_handshake(parms);
		break;
	default:
		tlshd_log_debug("Unrecognized auth mode (%d)",
				parms->auth_mode);
	}
}

#ifdef HAVE_GNUTLS_QUIC
static int tlshd_quic_client_x509_verify_function(gnutls_session_t session)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);

	return tlshd_client_x509_verify_function(session, conn->parms);
}

static int tlshd_quic_client_ticket_recv(gnutls_session_t session, unsigned int htype,
					 unsigned int when, unsigned int incoming,
					 const gnutls_datum_t *msg)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	int ret, sockfd = conn->parms->sockfd;
	gnutls_datum_t ticket;

	if (htype != GNUTLS_HANDSHAKE_NEW_SESSION_TICKET)
		return 0;

	conn->completed = 1;
	ret = gnutls_session_get_data2(session, &ticket);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		return ret;
	}

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, ticket.data, ticket.size);
	if (ret) {
		tlshd_log_error("socket setsockopt session ticket error %d %u", errno, ticket.size);
		return -1;
	}
	tlshd_log_debug("  Ticket recv: %u %u %u", when, incoming, msg->size);
	return 0;
}

#define TLSHD_QUIC_NO_CERT_AUTH	3

static int tlshd_quic_client_set_x509_session(struct tlshd_quic_conn *conn)
{
	struct tlshd_handshake_parms *parms = conn->parms;
	gnutls_certificate_credentials_t cred;
	gnutls_session_t session;
	int ret = -EINVAL;
	char *cafile;

	if (conn->cert_req != TLSHD_QUIC_NO_CERT_AUTH) {
		if (!tlshd_x509_client_get_certs(parms) || !tlshd_x509_client_get_privkey(parms)) {
			tlshd_log_error("cert/privkey get error %d", -ret);
			return ret;
		}
	}
	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	if (tlshd_config_get_client_truststore(&cafile)) {
		ret = gnutls_certificate_set_x509_trust_file(cred, cafile, GNUTLS_X509_FMT_PEM);
		free(cafile);
	} else
		ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	tlshd_log_debug("System trust: Loaded %d certificate(s).", ret);

	if (conn->cert_req == TLSHD_QUIC_NO_CERT_AUTH) {
		gnutls_certificate_set_verify_flags(cred, GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 |
							  GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5);
		gnutls_certificate_set_flags(cred, GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH |
						   GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK);
	} else {
		gnutls_certificate_set_verify_function(cred,
						       tlshd_quic_client_x509_verify_function);
		gnutls_certificate_set_retrieve_function2(cred, tlshd_x509_retrieve_key_cb);
	}

	ret = gnutls_init(&session, GNUTLS_CLIENT |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, tlshd_quic_client_ticket_recv);
	gnutls_session_set_ptr(session, conn);
	if (conn->ticket_len) {
		ret = gnutls_session_set_data(session, conn->ticket, conn->ticket_len);
		if (ret)
			goto err_session;
	}
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;
	if (parms->peername) {
		ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS,
					     parms->peername, strlen(parms->peername));
		if (ret)
			goto err_session;
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	tlshd_log_gnutls_error(ret);
	return ret;
}

static int tlshd_quic_client_set_anon_session(struct tlshd_quic_conn *conn)
{
	conn->cert_req = TLSHD_QUIC_NO_CERT_AUTH;
	return tlshd_quic_client_set_x509_session(conn);
}

static int tlshd_quic_client_set_psk_session(struct tlshd_quic_conn *conn)
{
	key_serial_t peerid = conn->parms->peerids[0];
	gnutls_psk_client_credentials_t cred;
	gnutls_session_t session;
	char *identity = NULL;
	gnutls_datum_t key;
	int ret = -EINVAL;

	if (!tlshd_keyring_get_psk_username(peerid, &identity) ||
	    !tlshd_keyring_get_psk_key(peerid, &key)) {
		free(identity);
		tlshd_log_error("identity/key get error %d", -ret);
		return ret;
	}

	ret = gnutls_psk_allocate_client_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_psk_set_client_credentials(cred, identity, &key, GNUTLS_PSK_KEY_RAW);
	if (ret)
		goto err_cred;

	ret = gnutls_init(&session, GNUTLS_CLIENT);
	if (ret)
		goto err_cred;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, tlshd_quic_client_ticket_recv);
	gnutls_session_set_ptr(session, conn);
	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret)
		goto err_session;
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_client_credentials(cred);
err:
	free(identity);
	tlshd_log_gnutls_error(ret);
	return ret;
}

/**
 * tlshd_quic_clienthello_handshake - send a QUIC Client Initial
 * @parms: handshake parameters
 *
 */
void tlshd_quic_clienthello_handshake(struct tlshd_handshake_parms *parms)
{
	struct tlshd_quic_conn *conn;
	int ret;

	ret = tlshd_quic_conn_create(&conn, parms);
	if (ret) {
		parms->session_status = -ret;
		return gnutls_global_deinit();
	}

	switch (parms->auth_mode) {
	case HANDSHAKE_AUTH_UNAUTH:
		ret = tlshd_quic_client_set_anon_session(conn);
		break;
	case HANDSHAKE_AUTH_X509:
		ret = tlshd_quic_client_set_x509_session(conn);
		break;
	case HANDSHAKE_AUTH_PSK:
		ret = tlshd_quic_client_set_psk_session(conn);
		break;
	default:
		ret = -EINVAL;
		tlshd_log_debug("Unrecognized auth mode (%d)", parms->auth_mode);
	}
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	tlshd_quic_start_handshake(conn);
out:
	parms->session_status = conn->errcode;
	tlshd_quic_conn_destroy(conn);
}
#else
void tlshd_quic_clienthello_handshake(struct tlshd_handshake_parms *parms)
{
	tlshd_log_debug("QUIC handshake is not enabled (%d)", parms->auth_mode);
	parms->session_status = EOPNOTSUPP;
}
#endif
