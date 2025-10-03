/**
 * @file server.c
 * @brief Perform a TLSv1.3 server-side handshake
 *
 * @copyright
 * Copyright (c) 2023 Oracle and/or its affiliates.
 * Copyright (c) 2024 Red Hat, Inc.
 */

/*
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

#include <config.h>

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

/**
 * @var gnutls_privkey_t tlshd_server_pq_privkey
 * Server peer's post-quantum private key
 */
static gnutls_privkey_t tlshd_server_pq_privkey;

/**
 * @var gnutls_privkey_t tlshd_server_privkey
 * Server peer's RSA private key
 */
static gnutls_privkey_t tlshd_server_privkey;

/**
 * @var unsigned int tlshd_server_pq_certs_len
 * Count of server peer's PQ certificates
 */
static unsigned int tlshd_server_pq_certs_len = TLSHD_MAX_CERTS;

/**
 * @var unsigned int tlshd_server_certs_len
 * Count of server peer's certificates
 */
static unsigned int tlshd_server_certs_len = TLSHD_MAX_CERTS;

/**
 * @var gnutls_pcert_st tlshd_server_certs
 * Server peer's certificates
 */
static gnutls_pcert_st tlshd_server_certs[TLSHD_MAX_CERTS];

/**
 * @var gnutls_pk_algorithm_t tlshd_server_pq_pkalg
 * Server peer certificate's public key algorithms
 */
static gnutls_pk_algorithm_t tlshd_server_pq_pkalg = GNUTLS_PK_UNKNOWN;

/**
 * @brief Retrieve server certificates to be used for ServerHello
 * @param[in]     parms  Handshake parameters
 *
 * @retval true   Server certificates were found. Caller must release
 *		  the certificates using tlshd_x509_server_put_certs.
 * @retval false  No usable server certificates were found
 */
static bool tlshd_x509_server_get_certs(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_cert != TLS_NO_CERT)
		return tlshd_keyring_get_certs(parms->x509_cert,
					       tlshd_server_certs,
					       &tlshd_server_certs_len);
	return tlshd_config_get_certs(PEER_TYPE_SERVER, tlshd_server_certs,
				      &tlshd_server_pq_certs_len,
				      &tlshd_server_certs_len,
				      &tlshd_server_pq_pkalg);
}

/**
 * @brief Release server certificates that were used for ServerHello
 */
static void tlshd_x509_server_put_certs(void)
{
	unsigned int i;

	for (i = 0; i < TLSHD_MAX_CERTS; i++)
		gnutls_pcert_deinit(&tlshd_server_certs[i]);
}

/**
 * @brief Retrieve the private key to be used for ServerHello
 * @param[in]     parms  Handshake parameters
 *
 * @retval true   Private key was found. Caller must release the
 *		  private key using tlshd_x509_server_put_privkey.
 * @retval false  No usable private key was found
 */
static bool tlshd_x509_server_get_privkey(struct tlshd_handshake_parms *parms)
{
	if (parms->x509_privkey != TLS_NO_PRIVKEY)
		return tlshd_keyring_get_privkey(parms->x509_privkey,
						 &tlshd_server_privkey);
	return tlshd_config_get_privkey(PEER_TYPE_SERVER,
					&tlshd_server_pq_privkey,
					&tlshd_server_privkey);
}

/**
 * @brief Release the private key that was used for ServerHello
 */
static void tlshd_x509_server_put_privkey(void)
{
	gnutls_privkey_deinit(tlshd_server_pq_privkey);
	gnutls_privkey_deinit(tlshd_server_privkey);
}

/**
 * @brief Audit trust chain of incoming client certificate
 * @param[in]     req_ca_rdn
 * @param[in]     nreqs
 */
static void tlshd_x509_log_issuers(const gnutls_datum_t *req_ca_rdn, int nreqs)
{
	char issuer_dn[256];
	int i;

	if (nreqs < 1)
		return;

	tlshd_log_debug("Server's trusted authorities:");

	for (i = 0; i < nreqs; i++) {
		size_t len;
		int ret;

		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
		if (ret >= 0)
			tlshd_log_debug("   [%d]: %s", i, issuer_dn);
	}
}

/**
 * @brief Initialize the server peer's x.509 identity
 * @param[in]     session  session in the midst of a handshake
 * @param[in]     req_ca_rdn
 * @param[in]     nreqs
 * @param[in]     pk_algos
 * @param[in]     pk_algos_length
 * @param[out]    pcert
 * @param[out]    pcert_length
 * @param[out]    privkey
 *
 * @retval 0   Success; output parameters are set accordingly
 * @retval -1  Failure
 *
 * Callback function is of type gnutls_certificate_retrieve_function2
 *
 * Initial implementation based on the cert_callback() function in
 * gnutls/doc/examples/ex-cert-select.c.
 *
 * Sketched-in and untested.
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
#ifdef HAVE_GNUTLS_MLDSA
	gnutls_sign_algorithm_t client_alg;
	bool use_pq_cert = false;
	int i, ret;
#endif /* HAVE_GNUTLS_MLDSA */

	tlshd_x509_log_issuers(req_ca_rdn, nreqs);

	type = gnutls_certificate_type_get(session);
	if (type != GNUTLS_CRT_X509)
		return -1;

#ifdef HAVE_GNUTLS_MLDSA
	/*
 	 * NB: Unfortunately when the callback function is invoked server-side,
 	 * pk_algos is NULL and pk_algos_length is 0. So we check the signature
 	 * algorithms the client supports and try to match one of them to the
 	 * public-key algorithm used by the server cert.
 	 */
	if (tlshd_server_pq_pkalg != GNUTLS_PK_UNKNOWN) {
		for (i = 0; ; i++) {
			ret = gnutls_sign_algorithm_get_requested(session, i, &client_alg);
			if (ret != GNUTLS_E_SUCCESS)
				break;
			switch (client_alg) {
			case GNUTLS_SIGN_MLDSA44:
				if (tlshd_server_pq_pkalg == GNUTLS_PK_MLDSA44)
					use_pq_cert = true;
				break;
			case GNUTLS_SIGN_MLDSA65:
				if (tlshd_server_pq_pkalg == GNUTLS_PK_MLDSA65)
					use_pq_cert = true;
				break;
			case GNUTLS_SIGN_MLDSA87:
				if (tlshd_server_pq_pkalg == GNUTLS_PK_MLDSA87)
					use_pq_cert = true;
				break;
			default:
				break;
			}
			if (use_pq_cert == true) {
				tlshd_log_debug("%s: Client supports %s", __func__,
						gnutls_sign_get_name(client_alg));
				break;
			}
		}
	}

	if (use_pq_cert == true) {
		tlshd_log_debug("%s: Selecting x509.pq.certificate from conf file", __func__);
		*pcert_length = tlshd_server_pq_certs_len;
		*pcert = tlshd_server_certs;
		*privkey = tlshd_server_pq_privkey;
	} else {
		tlshd_log_debug("%s: Selecting x509.certificate from conf file", __func__);
		*pcert_length = tlshd_server_certs_len;
		*pcert = tlshd_server_certs + tlshd_server_pq_certs_len;
		*privkey = tlshd_server_privkey;
	}
#else
	*pcert_length = tlshd_server_certs_len;
	*pcert = tlshd_server_certs;
	*privkey = tlshd_server_privkey;
#endif /* HAVE_GNUTLS_MLDSA */
	return 0;
}

/**
 * @brief Initialize server-side trust store
 * @param[out]    cred  Trust store to initialize
 *
 * @returns a GnuTLS error code. Caller must release credentials
 * using gnutls_certificate_free_credentials(3).
 */
static int tlshd_server_get_truststore(gnutls_certificate_credentials_t cred)
{
	char *pathname;
	int ret;

	if (tlshd_config_get_truststore(PEER_TYPE_SERVER, &pathname)) {
		ret = gnutls_certificate_set_x509_trust_file(cred, pathname,
							     GNUTLS_X509_FMT_PEM);
		free(pathname);
	} else
		ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		return ret;
	tlshd_log_debug("System trust: Loaded %d certificate(s).", ret);

	if (tlshd_config_get_crl(PEER_TYPE_SERVER, &pathname)) {
		ret = gnutls_certificate_set_x509_crl_file(cred, pathname,
							   GNUTLS_X509_FMT_PEM);
		free(pathname);
		if (ret < 0 ) {
			tlshd_log_gnutls_error(ret);
			return ret;
		}
		tlshd_log_debug("System CRL: Loaded %d CRL(s).", ret);
	}

	return GNUTLS_E_SUCCESS;
}

/**
 * @brief Verify remote's x.509 certificate
 * @param[in]     session  Session in the midst of a handshake
 * @param[in]     parms    Handshake parameters
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
static int tlshd_server_x509_verify_function(gnutls_session_t session,
					     struct tlshd_handshake_parms *parms)
{
	const gnutls_datum_t *peercerts;
	unsigned int i, status, num_peercerts;
	int ret;

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
	if (status)
		goto certificate_error;

	/* To do: Examine extended key usage information here, if we want
	 * to get picky. Kernel would have to tell us what to look for
	 * via a netlink attribute. */

	peercerts = gnutls_certificate_get_peers(session, &num_peercerts);
	if (!peercerts || num_peercerts == 0) {
		tlshd_log_debug("The peer cert list is empty.");
		goto certificate_error;
	}

	tlshd_log_debug("The peer offered %u certificate(s).",
			num_peercerts);

	for (i = 0; i < num_peercerts; i++) {
		gnutls_x509_crt_t cert;
		key_serial_t peerid;

		gnutls_x509_crt_init(&cert);
		ret = gnutls_x509_crt_import(cert, &peercerts[i],
					     GNUTLS_X509_FMT_DER);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_gnutls_error(ret);
			gnutls_x509_crt_deinit(cert);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		peerid = UINT_MAX;
		g_array_append_val(parms->remote_peerids, peerid);
		gnutls_x509_crt_deinit(cert);
	}

	return GNUTLS_E_SUCCESS;

certificate_error:
	gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_ACCESS_DENIED);
	return GNUTLS_E_CERTIFICATE_ERROR;
}

/**
 * @brief Verify a remote peer's x.509 certificate (TLSv1.3)
 * @param[in]     session  session in the midst of a handshake
 *
 * @retval GNUTLS_E_SUCCESS            Certificate has been successfully verified
 * @retval GNUTLS_E_CERTIFICATE_ERROR  Certificate verification failed
 */
static int tlshd_tls13_server_x509_verify_function(gnutls_session_t session)
{
	struct tlshd_handshake_parms *parms = gnutls_session_get_ptr(session);

	return tlshd_server_x509_verify_function(session, parms);
}

/**
 * @brief Process an x.509-based TLS handshake with a server certificate
 * @param[in]     parms  Handshake parameters
 */
static void tlshd_tls13_server_x509_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return;
	}
	ret = tlshd_server_get_truststore(xcred);
	if (ret != GNUTLS_E_SUCCESS)
		goto out_free_creds;

	if (!tlshd_x509_server_get_certs(parms))
		goto out_free_creds;
	if (!tlshd_x509_server_get_privkey(parms))
		goto out_free_certs;
	gnutls_certificate_set_retrieve_function2(xcred,
						  tlshd_x509_retrieve_key_cb);

	ret = gnutls_init(&session, GNUTLS_SERVER);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_certs;
	}
	gnutls_transport_set_int(session, parms->sockfd);
	gnutls_session_set_ptr(session, parms);

	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out_free_certs;
	}
	gnutls_certificate_set_verify_function(xcred,
					       tlshd_tls13_server_x509_verify_function);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	ret = tlshd_gnutls_priority_set(session, parms, 0);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		goto out_free_certs;
	}

	tlshd_start_tls_handshake(session, parms);

	if (tlshd_debug &&
	    gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {
		const gnutls_datum_t *peercerts;
		unsigned int i, num_certs = 0;

		peercerts = gnutls_certificate_get_peers(session, &num_certs);
		for (i = 0; i < num_certs; i++) {
			gnutls_x509_crt_t cert;
			gnutls_datum_t cinfo;

			gnutls_x509_crt_init(&cert);
			gnutls_x509_crt_import(cert, &peercerts[i],
					       GNUTLS_X509_FMT_DER);
			if (gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_ONELINE,
						  &cinfo) == 0) {
				tlshd_log_debug("Peer certificate: %s", cinfo.data);
				gnutls_free(cinfo.data);
			}
			gnutls_x509_crt_deinit(cert);
		}
	}

	gnutls_deinit(session);

out_free_certs:
	tlshd_x509_server_put_privkey();
	tlshd_x509_server_put_certs();

out_free_creds:
	gnutls_certificate_free_credentials(xcred);
}

/**
 * @brief Validate the remote peer's username
 * @param[in]     session   Session in the midst of a handshake
 * @param[in]     username  Remote peer's username
 * @param[in]     key       PSK matching "username"
 *
 * Searches for a key with description "username" in the session
 * keyring, and stores the PSK data in "key" if found.
 *
 * @retval 0  Matching key has been stored in "key"
 * @retval -1 Error during lookup, "key" is not updated
 */
static int tlshd_server_psk_cb(gnutls_session_t session,
			       const char *username, gnutls_datum_t *key)
{
	struct tlshd_handshake_parms *parms;
	key_serial_t psk;
	long ret;

	parms = gnutls_session_get_ptr(session);

	ret = keyctl_search(KEY_SPEC_SESSION_KEYRING,
			    TLS_DEFAULT_PSK_TYPE, username, 0);
	if (ret < 0) {
		tlshd_log_error("failed to search '%s' key '%s'",
				TLS_DEFAULT_PSK_TYPE, username);
		return -1;
	}

	psk = (key_serial_t)ret;
	if (!tlshd_keyring_get_psk_key(psk, key)) {
		tlshd_log_error("failed to load key %lu", (unsigned long)psk);
		return -1;
	}

	/* PSK uses the same identity for both client and server */
	g_array_append_val(parms->remote_peerids, psk);
	return 0;
}

/**
 * @brief Process an PSK-based TLS handshake (TLSv1.3)
 * @param[in]     parms   Handshake parameters
 */
static void tlshd_tls13_server_psk_handshake(struct tlshd_handshake_parms *parms)
{
	gnutls_psk_server_credentials_t psk_cred;
	gnutls_session_t session;
	int ret;

#ifdef HAVE_GNUTLS_PSK_ALLOCATE_CREDENTIALS2
	ret = gnutls_psk_allocate_server_credentials2(&psk_cred,
						      GNUTLS_MAC_UNKNOWN);
#else
	ret = gnutls_psk_allocate_server_credentials(&psk_cred);
#endif
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

	ret = tlshd_gnutls_priority_set(session, parms, 0);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		goto out_free_creds;
	}

	tlshd_start_tls_handshake(session, parms);

	gnutls_deinit(session);

out_free_creds:
	gnutls_psk_free_server_credentials(psk_cred);
}

/**
 * @brief Send a TLSv1.3 ServerHello
 * @param[in]     parms  Handshake parameters
 */
void tlshd_tls13_serverhello_handshake(struct tlshd_handshake_parms *parms)
{
	switch (parms->auth_mode) {
	case HANDSHAKE_AUTH_X509:
		tlshd_tls13_server_x509_handshake(parms);
		break;
	case HANDSHAKE_AUTH_PSK:
		tlshd_tls13_server_psk_handshake(parms);
		break;
	default:
		tlshd_log_debug("Unrecognized auth mode (%d)",
				parms->auth_mode);
	}
}

#ifdef HAVE_GNUTLS_QUIC
/**
 * @brief Verify the ALPNs presented by a remote peer
 * @param[in]      session
 * @param[in]      htype
 * @param[in]      when
 * @param[in]      incoming
 * @param[in]      msg
 *
 * @retval 0   ALPN verification was successful
 * @retval -1  ALPN verification failed
 */
static int tlshd_quic_server_alpn_verify(gnutls_session_t session, unsigned int htype,
					 unsigned int when, unsigned int incoming,
					 const gnutls_datum_t *msg)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_datum_t alpn = {};
	int ret;

	if (!conn->alpns[0])
		return 0;

	ret = gnutls_alpn_get_selected_protocol(session, &alpn);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		return ret;
	}
	if (setsockopt(conn->parms->sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn.data, alpn.size)) {
		tlshd_log_error("socket setsockopt alpn error %d %u", errno, alpn.size);
		return -1;
	}
	tlshd_log_debug("  ALPN verify: %u %u %u %u", htype, when, incoming, msg->size);
	return 0;
}

/**
 * @brief Anti-reply protection
 * @param[in]     dbf
 * @param[in]     exp_time
 * @param[in]     key
 * @param[in]     data
 *
 * Currently, tlshd handles each handshake request in a new process
 * rather than a thread. As a result, it cannot share the
 * gnutls_anti_replay_t object across processes. This causes 0-RTT
 * data to be automatically disabled, since
 * _gnutls_anti_replay_check() fails validation in the absence of a
 * shared anti-replay context.
 *
 * To properly support 0-RTT data, we need to enable sharing of the
 * gnutls_anti_replay_t object across processes in some way.
 *
 * @retval 0  Not a replay
 */
static int tlshd_quic_server_anti_replay_db_add_func(void *dbf, time_t exp_time,
						     const gnutls_datum_t *key,
						     const gnutls_datum_t *data)
{
	tlshd_log_debug("  Anti replay: %u %u %u %u", !!dbf, exp_time, key->size, data->size);
	return 0;
}

/**
 * @var gnutls_anti_replay_t tlshd_quic_server_anti_replay
 * Shared anti-replay context
 */
static gnutls_anti_replay_t tlshd_quic_server_anti_replay;

/**
 * @brief Verify a remote peer's x.509 certificate (QUIC)
 * @param[in]     session  session in the midst of a handshake
 *
 * @retval GNUTLS_E_SUCCESS            Certificate has been successfully verified
 * @retval GNUTLS_E_CERTIFICATE_ERROR  Certificate verification failed
 */
static int tlshd_quic_server_x509_verify_function(gnutls_session_t session)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);

	return tlshd_server_x509_verify_function(session, conn->parms);
}

/**
 * @brief Validate the remote peer's username
 * @param[in]     session   Session in the midst of a handshake
 * @param[in]     username  Remote peer's username
 * @param[in]     key       PSK matching "username"
 *
 * Searches for a key with description "username" in the session
 * keyring, and stores the PSK data in "key" if found.
 *
 * @retval 0  Matching key has been stored in "key"
 * @retval -1 Error during lookup, "key" is not updated
 */
static int tlshd_quic_server_psk_cb(gnutls_session_t session, const char *username,
				    gnutls_datum_t *key)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	struct tlshd_handshake_parms *parms = conn->parms;
	key_serial_t psk;
	long ret;

	ret = keyctl_search(KEY_SPEC_SESSION_KEYRING, "psk", username, 0);
	if (ret >= 0)
		goto found;

	ret = keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", username, 0);
	if (ret < 0) {
		tlshd_log_error("key search error %d %s", errno, username);
		return -1;
	}

found:
	psk = (key_serial_t)ret;
	if (!tlshd_keyring_get_psk_key(psk, key)) {
		tlshd_log_error("key load error %d", errno);
		return -1;
	}

	/* PSK uses the same identity for both client and server */
	g_array_append_val(parms->remote_peerids, psk);
	return 0;
}

/**
 * @brief Prepare a session for a QUIC server handshake using an x.509 cert
 * @param[in]     conn
 */
static void tlshd_quic_server_set_x509_session(struct tlshd_quic_conn *conn)
{
	struct tlshd_handshake_parms *parms = conn->parms;
	gnutls_certificate_credentials_t cred;
	gnutls_datum_t ticket_key;
	gnutls_session_t session;
	int ret;

	if (!tlshd_x509_server_get_certs(parms) || !tlshd_x509_server_get_privkey(parms)) {
		tlshd_log_error("Failed to get cert or privkey");
		return;
	}

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = tlshd_server_get_truststore(cred);
	if (ret)
		goto err;

	gnutls_certificate_set_retrieve_function2(cred, tlshd_x509_retrieve_key_cb);

	gnutls_certificate_set_verify_function(cred, tlshd_quic_server_x509_verify_function);

	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;

	if (!tlshd_quic_server_anti_replay) {
		ret = gnutls_anti_replay_init(&tlshd_quic_server_anti_replay);
		if (ret)
			goto err_session;
		gnutls_anti_replay_set_add_function(tlshd_quic_server_anti_replay,
						    tlshd_quic_server_anti_replay_db_add_func);
		gnutls_anti_replay_set_ptr(tlshd_quic_server_anti_replay, NULL);
	}
	gnutls_anti_replay_enable(session, tlshd_quic_server_anti_replay);
	ret = gnutls_record_set_max_early_data_size(session, 0xffffffffu);
	if (ret)
		goto err_session;

	gnutls_session_set_ptr(session, conn);
	ticket_key.data = conn->ticket;
	ticket_key.size = conn->ticket_len;
	ret = gnutls_session_ticket_enable_server(session, &ticket_key);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, tlshd_quic_server_alpn_verify);
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;
	gnutls_certificate_server_set_request(session, conn->cert_req);

	conn->is_serv = 1;
	conn->session = session;
	return;

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	tlshd_x509_server_put_privkey();
	tlshd_x509_server_put_certs();
	tlshd_log_gnutls_error(ret);
}

/**
 * @brief Prepare a session for a QUIC client handshake using a pre-shared key
 * @param[in]     conn
 */
static void tlshd_quic_server_set_psk_session(struct tlshd_quic_conn *conn)
{
	gnutls_psk_server_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_psk_allocate_server_credentials(&cred);
	if (ret)
		goto err;
	gnutls_psk_set_server_credentials_function(cred, tlshd_quic_server_psk_cb);

	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err_cred;
	gnutls_session_set_ptr(session, conn);
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, tlshd_quic_server_alpn_verify);
	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret)
		goto err_session;

	conn->is_serv = 1;
	conn->session = session;
	return;

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_server_credentials(cred);
err:
	tlshd_log_gnutls_error(ret);
}

/**
 * @brief Send a QUIC Server Initial
 * @param[in]     parms  Handshake parameters
 */
void tlshd_quic_serverhello_handshake(struct tlshd_handshake_parms *parms)
{
	struct tlshd_quic_conn *conn;
	int ret;

	ret = tlshd_quic_conn_create(&conn, parms);
	if (ret) {
		parms->session_status = -ret;
		return;
	}

	switch (parms->auth_mode) {
	case HANDSHAKE_AUTH_X509:
		tlshd_quic_server_set_x509_session(conn);
		break;
	case HANDSHAKE_AUTH_PSK:
		tlshd_quic_server_set_psk_session(conn);
		break;
	default:
		tlshd_log_debug("Unrecognized auth mode (%d)", parms->auth_mode);
	}
	if (!conn->session)
		goto out;

	tlshd_quic_start_handshake(conn);
	parms->session_status = conn->errcode;
out:
	tlshd_quic_conn_destroy(conn);
}
#else
/**
 * @brief Send a QUIC Server Initial
 * @param[in]     parms  Handshake parameters
 */
void tlshd_quic_serverhello_handshake(struct tlshd_handshake_parms *parms)
{
	tlshd_log_debug("QUIC handshake is not enabled (%d)", parms->auth_mode);
	parms->session_status = EOPNOTSUPP;
}
#endif
