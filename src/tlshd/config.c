/*
 * Parse tlshd's config file.
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
#include <sys/stat.h>
#include <sys/syscall.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <netlink/netlink.h>

#include <glib.h>

#include "tlshd.h"

static GKeyFile *tlshd_configuration;

/**
 * tlshd_config_init - Read tlshd's config file
 * @pathname: Pathname to config file
 *
 * Return values:
 *   %true: Config file read successfully
 *   %false: Unable to read config file
 */
bool tlshd_config_init(const gchar *pathname)
{
	gchar **keyrings;
	gsize i, length;
	GError *error;
	gint tmp;

	tlshd_configuration = g_key_file_new();

	error = NULL;
	if (!g_key_file_load_from_file(tlshd_configuration, pathname,
				       G_KEY_FILE_KEEP_COMMENTS,
				       &error)) {
		tlshd_log_gerror("Failed to load config file", error);
		g_error_free(error);
		return false;
	}

	/*
	 * These calls return zero if the key isn't present or the
	 * specified key value is invalid.
	 */
	tlshd_debug = g_key_file_get_integer(tlshd_configuration, "debug",
					     "loglevel", NULL);
	tlshd_tls_debug = g_key_file_get_integer(tlshd_configuration,
						 "debug", "tls", NULL);
	nl_debug = g_key_file_get_integer(tlshd_configuration, "debug",
					  "nl", NULL);
	tmp = g_key_file_get_integer(tlshd_configuration, "debug",
				     "delay_done", NULL);
	tlshd_delay_done = tmp > 0 ? (unsigned int)tmp : 0;

	keyrings = g_key_file_get_string_list(tlshd_configuration,
					      "authenticate",
					      "keyrings", &length, NULL);
	if (keyrings) {
		for (i = 0; i < length; i++) {
			if (!strcmp(keyrings[i], ".nvme"))
				continue;
			if (!strcmp(keyrings[i], ".nfs"))
				continue;
			if (!strcmp(keyrings[i], ".nfsd"))
				continue;
			tlshd_keyring_link_session(keyrings[i]);
		}
		g_strfreev(keyrings);
	}
	/* The ".nvme", ".nfs", and ".nfsd" keyrings cannot be disabled. */
	tlshd_keyring_link_session(".nvme");
	tlshd_keyring_link_session(".nfs");
	tlshd_keyring_link_session(".nfsd");

	return true;
}

void tlshd_config_shutdown(void)
{
	g_key_file_free(tlshd_configuration);
}

/**
 * ALLPERMS exists in glibc, but not on musl, so we manually
 * define TLSHD_ACCESSPERMS instead of using ALLPERMS.
 */
#define TLSHD_ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)

/*
 * Expected file attributes
 */
#define TLSHD_OWNER		0	/* root */
#define TLSHD_CERT_MODE		(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define TLSHD_PRIVKEY_MODE	(S_IRUSR|S_IWUSR)

/*
 * On success, caller must release buffer returned in @data by calling free(3)
 */
static bool tlshd_config_read_datum(const char *pathname, gnutls_datum_t *data,
				    uid_t owner, mode_t mode)
{
	struct stat statbuf;
	unsigned int size;
	void *buf;
	bool ret;
	int fd;

	ret = false;

	fd = open(pathname, O_RDONLY);
	if (fd == -1) {
		if (access(pathname, F_OK))
			tlshd_log_debug("tlshd cannot access \"%s\"",
					pathname);
		else
			tlshd_log_perror("open");
		goto out;
	}
	if (fstat(fd, &statbuf)) {
		tlshd_log_perror("stat");
		goto out_close;
	}
	if (statbuf.st_size < 0 || statbuf.st_size > INT_MAX) {
		tlshd_log_error("Bad config file size: %lld", statbuf.st_size);
		goto out_close;
	}
	size = (unsigned int)statbuf.st_size;
	if (statbuf.st_uid != owner)
		tlshd_log_notice("File %s: expected owner %u",
				 pathname, owner);
	if ((statbuf.st_mode & TLSHD_ACCESSPERMS) != mode)
		tlshd_log_notice("File %s: expected mode %o",
				 pathname, mode);
	buf = malloc(size);
	if (!buf) {
		errno = ENOMEM;
		tlshd_log_perror("malloc");
		goto out_close;
	}
	if (read(fd, buf, size) == -1) {
		tlshd_log_perror("read");
		free(buf);
		goto out_close;
	}
	data->data = buf;
	data->size = size;
	ret = true;

out_close:
	close(fd);
out:
	return ret;
}

/**
 * tlshd_config_get_client_truststore - Get truststore for ClientHello from .conf
 * @bundle: OUT: pathname to truststore
 *
 * Return values:
 *   %false: pathname not retrieved
 *   %true: pathname retrieved successfully; caller must free @bundle using free(3)
 */
bool tlshd_config_get_client_truststore(char **bundle)
{
	gchar *pathname;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.client",
					 "x509.truststore", NULL);
	if (!pathname)
		return false;
	if (access(pathname, F_OK)) {
		tlshd_log_debug("tlshd cannot access \"%s\"", pathname);
		g_free(pathname);
		return false;
	}

	*bundle = strdup(pathname);
	g_free(pathname);
	if (!*bundle)
		return false;

	tlshd_log_debug("Client x.509 truststore is %s", *bundle);
	return true;
}

/**
 * tlshd_config_get_client_crl - Get CRL for ClientHello from .conf
 * @result: OUT: pathname to CRL
 *
 * Return values:
 *   %false: pathname not retrieved
 *   %true: pathname retrieved successfully; caller must free @result using free(3)
 */
bool tlshd_config_get_client_crl(char **result)
{
	gchar *pathname;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.client",
					 "x509.crl", NULL);
	if (!pathname)
		return false;
	if (access(pathname, F_OK)) {
		tlshd_log_debug("tlshd cannot access \"%s\"", pathname);
		g_free(pathname);
		return false;
	}

	*result = strdup(pathname);
	g_free(pathname);
	if (!*result)
		return false;

	tlshd_log_debug("Client x.509 crl is %s", *result);
	return true;
}

/**
 * tlshd_config_get_client_certs - Get certs for ClientHello from .conf
 * @certs: OUT: in-memory certificates
 * @certs_len: IN: maximum number of certs to get, OUT: number of certs found
 *
 * Return values:
 *   %true: certificate retrieved successfully
 *   %false: certificate not retrieved
 */
bool tlshd_config_get_client_certs(gnutls_pcert_st *certs,
				   unsigned int *certs_len)
{
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.client",
					"x509.certificate", NULL);
	if (!pathname)
		return false;

	if (!tlshd_config_read_datum(pathname, &data, TLSHD_OWNER,
				     TLSHD_CERT_MODE)) {
		g_free(pathname);
		return false;
	}

	/* Config file supports only PEM-encoded certificates */
	ret = gnutls_pcert_list_import_x509_raw(certs, certs_len, &data,
						GNUTLS_X509_FMT_PEM, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		g_free(pathname);
		return false;
	}

	tlshd_log_debug("Retrieved %u x.509 client certificate(s) from %s",
			*certs_len, pathname);
	g_free(pathname);
	return true;
}

/**
 * tlshd_config_get_client_privkey - Get private key for ClientHello from .conf
 * @privkey: OUT: in-memory private key
 *
 * Return values:
 *   %true: private key retrieved successfully
 *   %false: private key not retrieved
 */
bool tlshd_config_get_client_privkey(gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.client",
					"x509.private_key", NULL);
	if (!pathname)
		return false;

	if (!tlshd_config_read_datum(pathname, &data, TLSHD_OWNER,
				     TLSHD_PRIVKEY_MODE)) {
		g_free(pathname);
		return false;
	}

	ret = gnutls_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(data.data);
		g_free(pathname);
		return false;
	}

	/* Config file supports only PEM-encoded keys */
	ret = gnutls_privkey_import_x509_raw(*privkey, &data,
					     GNUTLS_X509_FMT_PEM, NULL, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		g_free(pathname);
		return false;
	}

	tlshd_log_debug("Retrieved private key from %s", pathname);
	g_free(pathname);
	return true;
}

/**
 * tlshd_config_get_server_truststore - Get truststore for ServerHello from .conf
 * @bundle: OUT: pathname to truststore
 *
 * Return values:
 *   %false: pathname not retrieved
 *   %true: pathname retrieved successfully; caller must free @bundle using free(3)
 */
bool tlshd_config_get_server_truststore(char **bundle)
{
	gchar *pathname;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.server",
					 "x509.truststore", NULL);
	if (!pathname)
		return false;
	if (access(pathname, F_OK)) {
		tlshd_log_debug("tlshd cannot access \"%s\"", pathname);
		g_free(pathname);
		return false;
	}

	*bundle = strdup(pathname);
	g_free(pathname);
	if (!*bundle)
		return false;

	tlshd_log_debug("Server x.509 truststore is %s", *bundle);
	return true;
}

/**
 * tlshd_config_get_server_crl - Get CRL for ServerHello from .conf
 * @result: OUT: pathname to CRL
 *
 * Return values:
 *   %false: pathname not retrieved
 *   %true: pathname retrieved successfully; caller must free @result using free(3)
 */
bool tlshd_config_get_server_crl(char **result)
{
	gchar *pathname;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.server",
					 "x509.crl", NULL);
	if (!pathname)
		return false;
	if (access(pathname, F_OK)) {
		tlshd_log_debug("tlshd cannot access \"%s\"", pathname);
		g_free(pathname);
		return false;
	}

	*result = strdup(pathname);
	g_free(pathname);
	if (!*result)
		return false;

	tlshd_log_debug("Server x.509 crl is %s", *result);
	return true;
}

/**
 * tlshd_config_get_server_certs - Get certs for ServerHello from .conf
 * @certs: OUT: in-memory certificates
 * @certs_len: IN: maximum number of certs to get, OUT: number of certs found
 *
 * Return values:
 *   %true: certificate retrieved successfully
 *   %false: certificate not retrieved
 */
bool tlshd_config_get_server_certs(gnutls_pcert_st *certs,
				   unsigned int *certs_len)
{
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.server",
					"x509.certificate", NULL);
	if (!pathname)
		return false;

	if (!tlshd_config_read_datum(pathname, &data, TLSHD_OWNER,
				     TLSHD_CERT_MODE)) {
		g_free(pathname);
		return false;
	}

	/* Config file supports only PEM-encoded certificates */
	ret = gnutls_pcert_list_import_x509_raw(certs, certs_len, &data,
						GNUTLS_X509_FMT_PEM, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		g_free(pathname);
		return false;
	}

	tlshd_log_debug("Retrieved %u x.509 server certificate(s) from %s",
			*certs_len, pathname);
	g_free(pathname);
	return true;
}

/**
 * tlshd_config_get_server_privkey - Get private key for ServerHello from .conf
 * @privkey: OUT: in-memory private key
 *
 * Return values:
 *   %true: private key retrieved successfully
 *   %false: private key not retrieved
 */
bool tlshd_config_get_server_privkey(gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.server",
					"x509.private_key", NULL);
	if (!pathname)
		return false;

	if (!tlshd_config_read_datum(pathname, &data, TLSHD_OWNER,
				     TLSHD_PRIVKEY_MODE)) {
		g_free(pathname);
		return false;
	}

	ret = gnutls_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(data.data);
		g_free(pathname);
		return false;
	}

	/* Config file supports only PEM-encoded keys */
	ret = gnutls_privkey_import_x509_raw(*privkey, &data,
					     GNUTLS_X509_FMT_PEM, NULL, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		g_free(pathname);
		return false;
	}

	tlshd_log_debug("Retrieved private key from %s", pathname);
	g_free(pathname);
	return true;
}
