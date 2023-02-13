/*
 * Scrape authentication information from kernel keyring.
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
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>

#include "tlshd.h"

long tlshd_keyring;

/**
 * tlshd_keyring_get_psk_username - Retrieve username for PSK handshake
 * @serial: Key serial number to look up
 * @username: On success, filled in with NUL-terminated user name
 *
 * Caller must use gnutls_free() to free @username when finished.
 *
 * Return values:
 *   %true: Success; @username has been initialized
 *   %false: Failure
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
 * tlshd_keyring_get_psk_key - Retrieve pre-shared key for PSK handshake
 * @serial: Key serial number to look up
 * @key: On success, filled in with pre-shared key
 *
 * Caller must use free() to free @key->data when finished.
 *
 * Return values:
 *   %true: Success; @key has been initialized
 *   %false: Failure
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
	key->size = ret;
	return true;
}

/**
 * tlshd_keyring_get_privkey - Retrieve privkey for x.509 handshake
 * @serial: Key serial number to look up
 * @privkey: On success, filled in with a private key
 *
 * Caller must use gnutls_privkey_deinit() to free @privkey when finished.
 *
 * Return values:
 *   %true: Success; @privkey has been initialized
 *   %false: Failure
 */
bool tlshd_keyring_get_privkey(key_serial_t serial, gnutls_privkey_t privkey)
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
	data.size = ret;

	ret = gnutls_privkey_init(&privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(tmp);
		return false;
	}

	/* Handshake upcall passes only DER-encoded keys */
	ret = gnutls_privkey_import_x509_raw(privkey, &data, GNUTLS_X509_FMT_DER,
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
 * tlshd_keyring_get_cert - Retrieve cert for x.509 handshake
 * @serial: Key serial number to look up
 * @cert: On success, filled in with certificate
 *
 * Caller must use gnutls_pcert_deinit() to free @cert when finished.
 *
 * Return values:
 *   %true: Success; @cert has been initialized
 *   %false: Failure
 */
bool tlshd_keyring_get_cert(key_serial_t serial, gnutls_pcert_st *cert)
{
	gnutls_datum_t data;
	void *tmp;
	int ret;

	ret = keyctl_read_alloc(serial, &tmp);
	if (ret < 0) {
		tlshd_log_perror("keyctl_read_alloc");
		tlshd_log_error("Failed to read TLS x.509 certificate.");
		return false;
	}
	data.data = tmp;
	data.size = ret;

	/* Handshake upcall passes only DER-encoded certificates */
	ret = gnutls_pcert_import_x509_raw(cert, &data,
					   GNUTLS_X509_FMT_DER, 0);
	free(tmp);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	tlshd_log_debug("Retrieved x.509 certificate");
	return true;
}

int tlshd_link_keyring(const char *keyring)
{
	long keyring_id = 0;
	char buf[1024];
	char *eptr = NULL;
	int ret;

	keyring_id = strtol(keyring, &eptr, 0);
	if (keyring == eptr) {
		FILE *fp;
		char typebuf[256];
		int ndesc, n, id;

		fp = fopen("/proc/keys", "r");
		if (!fp) {
			tlshd_log_perror("open");
			tlshd_log_error("Failed to open '/proc/keys'\n");
			return -1;
		}
		while (fgets(buf, sizeof(buf), fp)) {
			char *cp = strchr(buf, '\n');
			if (!cp)
				*cp = '\0';
			n = sscanf(buf, "%x %*s %*u %*s %*x %*d %*d keyring %s %n",
				   &id, typebuf, &ndesc);
			if (n != 2)
				continue;
			if (!strncmp(keyring, typebuf, strlen(keyring))) {
				keyring_id = id;
				break;
			}
		}
		fclose(fp);
		if (!keyring_id) {
			tlshd_log_error("Failed to convert keyring number");
			return -1;
		}
	}
	ret = keyctl_describe(keyring_id, buf, sizeof(buf));
	if (ret < 0) {
		tlshd_log_debug("Failed to lookup keyring %s (%lx) error %d\n",
				keyring, keyring_id, errno);
		errno = -ENOKEY;
		return -1;
	}
	ret = keyctl_link(keyring_id, KEY_SPEC_SESSION_KEYRING);
	if (ret < 0) {
		tlshd_log_debug("Failed to link keyring %s (%lx) error %d\n",
				keyring, keyring_id, errno);
		return -1;
	}
	tlshd_log_debug("Using keyring '%s'\n", buf);
	tlshd_keyring = keyring_id;
	return 0;
}

void tlshd_unlink_keyring(void)
{
	if (tlshd_keyring)
		keyctl_unlink(tlshd_keyring, KEY_SPEC_THREAD_KEYRING);
	tlshd_keyring = 0;
}
