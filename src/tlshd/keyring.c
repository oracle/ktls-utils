/**
 * @file keyring.c
 * @brief Linux keyring management
 *
 * @copyright
 * Copyright (c) 2022 Oracle and/or its affiliates.
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
#include <netdb.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>

#include "tlshd.h"

/**
 * @brief Retrieve username for PSK handshake
 * @param[in]     serial    Key serial number to look up
 * @param[out]    username  Filled in with NUL-terminated user name
 *
 * Caller must use gnutls_free() to free "username" when finished.
 *
 * @retval true  Success; "username" has been initialized
 * @retval false Failure
 */
bool tlshd_keyring_get_psk_username(key_serial_t serial, char **username)
{
	char *ptr, *psk_name;
	int ret;

	ret = keyctl_describe_alloc(serial, &psk_name);
	if (ret < 0) {
		tlshd_log_perror("keyctl_describe_alloc");
		tlshd_log_debug("Failed to describe key %08x.", serial);
		return false;
	}
	ptr = strrchr(psk_name, ';');
	if (!ptr)
		ptr = psk_name;
	else
		ptr++;

	*username = gnutls_malloc(strlen(ptr) + 1);
	if (!*username) {
		tlshd_log_error("Failed to allocate TLS psk identity.");
		free(psk_name);
		return false;
	}
	tlshd_log_debug("Using psk identity %s\n", ptr);
	strcpy(*username, ptr);
	free(psk_name);
	return true;
}

/**
 * @brief Retrieve pre-shared key for PSK handshake
 * @param[in]     serial   Key serial number to look up
 * @param[out]    key      Filled in with pre-shared key
 *
 * Caller must use free() to free "key->data" when finished.
 *
 * @retval true   Success; "key" has been initialized
 * @retval false  Failure
 */
bool tlshd_keyring_get_psk_key(key_serial_t serial, gnutls_datum_t *key)
{
	void *tmp;
	int ret;

	key->data = NULL;
	key->size = 0;

	ret = keyctl_read_alloc(serial, &tmp);
	if (ret < 0) {
		tlshd_log_perror("keyctl_read_alloc");
		tlshd_log_error("Failed to read TLS psk data.");
		return false;
	}

	key->data = tmp;
	key->size = (unsigned int)ret;
	return true;
}

/**
 * @brief Retrieve privkey for x.509 handshake
 * @param[in]     serial   Key serial number to look up
 * @param[out]    privkey  Filled in with a private key
 *
 * Caller must use gnutls_privkey_deinit() to free "privkey" when finished.
 *
 * @retval true   Success; "privkey" has been initialized
 * @retval false  Failure
 */
bool tlshd_keyring_get_privkey(key_serial_t serial, gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	void *tmp;
	int ret;

	ret = keyctl_read_alloc(serial, &tmp);
	if (ret < 0) {
		tlshd_log_perror("keyctl_read_alloc");
		tlshd_log_error("Failed to read TLS x.509 private key.");
		return false;
	}
	data.data = tmp;
	data.size = (unsigned int)ret;

	ret = gnutls_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(tmp);
		return false;
	}

	/* Handshake upcall passes only DER-encoded keys */
	ret = gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_DER,
					     NULL, 0);
	free(tmp);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	tlshd_log_debug("Retrieved private key");
	return true;
}

/**
 * @brief Retrieve certs for x.509 handshake
 * @param[in]     serial     Key serial number to look up
 * @param[out]    certs      On success, filled in with certificates
 * @param[in,out] certs_len  Maximum number of certs to get, number of certs found
 *
 * Caller must use gnutls_pcert_deinit() to free "cert" when finished.
 *
 * @retval true   Success; "cert" has been initialized
 * @retval false  Failure
 */
bool tlshd_keyring_get_certs(key_serial_t serial, gnutls_pcert_st *certs,
			     unsigned int *certs_len)
{
	gnutls_datum_t data;
	void *tmp;
	int ret;

	if (*certs_len == 0) {
		tlshd_log_error("tlshd_keyring_get_cert called with zero array.");
		return false;
	}

	ret = keyctl_read_alloc(serial, &tmp);
	if (ret < 0) {
		tlshd_log_perror("keyctl_read_alloc");
		tlshd_log_error("Failed to read TLS x.509 certificate.");
		return false;
	}
	data.data = tmp;
	data.size = (unsigned int)ret;

	/* Handshake upcall passes only DER-encoded certificates */
	ret = gnutls_pcert_import_x509_raw(certs, &data,
					   GNUTLS_X509_FMT_DER, 0);
	free(tmp);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	*certs_len = 1;
	tlshd_log_debug("Retrieved %u x.509 certificate(s) from keyring",
			*certs_len);
	return true;
}

/**
 * @brief Create key containing peer's certificate
 * @param[in]     cert      Initialized x.509 certificate
 * @param[in]     peername  Hostname of the remote peer
 *
 * @returns a positive key serial number on success; otherwise
 * TLS_NO_PEERID.
 */
key_serial_t tlshd_keyring_create_cert(gnutls_x509_crt_t cert,
				       const char *peername)
{
	key_serial_t serial = TLS_NO_PEERID;
	char description[NI_MAXHOST + 10];
	gnutls_datum_t out;
	int len, ret;

	len = snprintf(description, sizeof(description) - 1,
		       "TLS x509 %s", peername);
	if (len < 0 || (size_t)len >= sizeof(description)) {
		tlshd_log_error("Failed to construct key description.");
		goto out;
	}

	ret = gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &out);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out;
	}

	serial = add_key("asymmetric", description, out.data, out.size,
			 KEY_SPEC_USER_KEYRING);
	if (serial == -1) {
		tlshd_log_perror("add_key");
		serial = TLS_NO_PEERID;
	}

	gnutls_free(out.data);
out:
	return serial;
}

/**
 * @brief Link a keyring into the session keyring
 * @param[in]     keyring  keyring to be linked
 *
 * @retval 0   Success
 * @retval -1  Failure
 */
int tlshd_keyring_link_session(const char *keyring)
{
	key_serial_t serial;
	long ret;

	if (!keyring || keyring[0] == '\0') {
		tlshd_log_error("No keyring specified");
		return -1;
	}

	serial = find_key_by_type_and_desc("keyring", keyring, 0);
	if (serial == -1) {
		tlshd_log_debug("Failed to find keyring '%s'\n", keyring);
		return -1;
	}

	ret = keyctl_link(serial, KEY_SPEC_SESSION_KEYRING);
	if (ret < 0) {
		tlshd_log_debug("Failed to link keyring '%s' (%lx): %s\n",
				keyring, serial, strerror(errno));
		return -1;
	}

	tlshd_log_debug("Keyring '%s' linked into our session keyring.\n", keyring);
	return 0;
}
