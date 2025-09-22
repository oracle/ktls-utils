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

#include <config.h>

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
 * @legacy: Don't generate an error if the config file doesn't exist
 *
 * Return values:
 *   %true: Config file read successfully
 *   %false: Unable to read config file
 */
bool tlshd_config_init(const gchar *pathname, bool legacy)
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
		if (!legacy)
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
 * tlshd_config_get_truststore - Get truststore for {Client,Server}Hello from .conf
 * @peer_type: IN: peer type
 * @bundle: OUT: pathname to truststore
 *
 * Return values:
 *   %false: pathname not retrieved
 *   %true: pathname retrieved successfully; caller must free @bundle using free(3)
 */
bool tlshd_config_get_truststore(int peer_type, char **bundle)
{
	gchar *pathname;

	pathname = g_key_file_get_string(tlshd_configuration,
					 peer_type == PEER_TYPE_CLIENT ?
					 "authenticate.client" :
					 "authenticate.server",
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

	tlshd_log_debug("%s x.509 truststore is %s",
		        peer_type == PEER_TYPE_CLIENT ? "Client" : "Server",
			*bundle);
	return true;
}

/**
 * tlshd_config_get_crl - Get CRL for {Client,Server}Hello from .conf
 * @peer_type: IN: peer type
 * @result: OUT: pathname to CRL
 *
 * Return values:
 *   %false: pathname not retrieved
 *   %true: pathname retrieved successfully; caller must free @result using free(3)
 */
bool tlshd_config_get_crl(int peer_type, char **result)
{
	gchar *pathname;

	pathname = g_key_file_get_string(tlshd_configuration,
					 peer_type == PEER_TYPE_CLIENT ?
					 "authenticate.client" :
					 "authenticate.server",
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

	tlshd_log_debug("%s x.509 crl is %s",
			peer_type == PEER_TYPE_CLIENT ? "Client" : "Server",
			*result);
	return true;
}

#ifdef HAVE_GNUTLS_MLDSA
static bool tlshd_cert_check_pk_alg(gnutls_datum_t *data,
				    gnutls_pk_algorithm_t *pkalg)
{
	gnutls_x509_crt_t cert;
	gnutls_pk_algorithm_t pk_alg;
	int ret;

	ret = gnutls_x509_crt_init(&cert);
	if (ret < 0)
		return false;

	ret = gnutls_x509_crt_import(cert, data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		gnutls_x509_crt_deinit(cert);
		return false;
	}

	pk_alg = gnutls_x509_crt_get_pk_algorithm(cert, NULL);
	tlshd_log_debug("%s: certificate pk algorithm %s", __func__,
			gnutls_pk_algorithm_get_name(pk_alg));
	switch (pk_alg) {
	case GNUTLS_PK_MLDSA44:
	case GNUTLS_PK_MLDSA65:
	case GNUTLS_PK_MLDSA87:
		*pkalg = pk_alg;
		break;
	default:
		gnutls_x509_crt_deinit(cert);
		return false;
	}

	gnutls_x509_crt_deinit(cert);
	return true;
}
#else
static bool tlshd_cert_check_pk_alg(__attribute__ ((unused)) gnutls_datum_t *data,
				    __attribute__ ((unused)) gnutls_pk_algorithm_t *pkalg)
{
	tlshd_log_debug("%s: gnutls version does not have ML-DSA support",
			__func__);
	return false;
}
#endif /* HAVE_GNUTLS_MLDSA */

/**
 * __tlshd_config_get_certs - Helper for tlshd_config_get_certs()
 * @peer_type: IN: peer type
 * @certs: OUT: in-memory certificates
 * @certs_len: IN: maximum number of certs to get, OUT: number of certs found
 * @pkgalg: IN: if non-NULL, indicates we want to retrieve the PQ cert,
 *	 OUT: if non-NULL, store the PQ public-key alg that was used in the PQ cert
 *
 * Return values:
 *   %true: certificate retrieved successfully
 *   %false: certificate not retrieved
 */
static bool __tlshd_config_get_certs(int peer_type, gnutls_pcert_st *certs,
				     unsigned int *certs_len,
				     gnutls_pk_algorithm_t *pkalg)
{
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration,
					 peer_type == PEER_TYPE_CLIENT ?
					 "authenticate.client" :
					 "authenticate.server",
					 pkalg != NULL ?
					 "x509.pq.certificate" :
					 "x509.certificate",
					 NULL);
	if (!pathname)
		return false;

	if (!tlshd_config_read_datum(pathname, &data, TLSHD_OWNER,
				     TLSHD_CERT_MODE)) {
		g_free(pathname);
		return false;
	}

	if (pkalg && !tlshd_cert_check_pk_alg(&data, pkalg)) {
		tlshd_log_debug("%s: %s not using a PQ public-key algorithm",
				__func__, pathname);
		free(data.data);
		g_free(pathname);
		*certs_len = 0;
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

	tlshd_log_debug("Retrieved %u x.509 %s certificate(s) from %s",
			*certs_len,
			peer_type == PEER_TYPE_CLIENT ? "client" : "server",
			pathname);
	g_free(pathname);
	return true;
}

/**
 * tlshd_config_get_certs - Get certs for {Client,Server} Hello from .conf
 * @peer_type: IN: peer type
 * @certs: OUT: in-memory certificates
 * @pq_certs_len: IN: maximum number of PQ certs to get, OUT: number of PQ certs found
 * @certs_len: IN: maximum number of certs to get, OUT: number of certs found
 * @pkgalg: OUT: the PQ public-key alg that was used in the PQ cert
 *
 * Retrieve the PQ cert(s) first, then the RSA cert(s).  Both are stored in the
 * same list.  Note that @pq_certs_len is deducted from the available @certs_len
 * and is also used to determine the offset to store the RSA cert(s) in the
 * @certs array.
 *
 * Return values:
 *   %true: certificate retrieved successfully
 *   %false: certificate not retrieved
 */
bool tlshd_config_get_certs(int peer_type, gnutls_pcert_st *certs,
			    unsigned int *pq_certs_len,
			    unsigned int *certs_len,
			    gnutls_pk_algorithm_t *pkalg)
{
	bool ret;

	ret = __tlshd_config_get_certs(peer_type, certs, pq_certs_len, pkalg);

	if (ret == true)
		*certs_len -= *pq_certs_len;
	else
		*pq_certs_len = 0;

	return __tlshd_config_get_certs(peer_type, certs + *pq_certs_len,
					certs_len, NULL);
}

/**
 * __tlshd_config_get_privkey - Helper for tlshd_config_get_privkey()
 * @peer_type: IN: peer type
 * @privkey: OUT: in-memory private key
 * @pq: IN: if true, retrieve the PQ private key
 *
 * Return values:
 *   %true: private key retrieved successfully
 *   %false: private key not retrieved
 */
static bool __tlshd_config_get_privkey(int peer_type, gnutls_privkey_t *privkey, bool pq)
{
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration,
					 peer_type == PEER_TYPE_CLIENT ?
					 "authenticate.client" :
					 "authenticate.server",
					 pq == true ?
					 "x509.pq.private_key" :
					 "x509.private_key",
					 NULL);
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
 * tlshd_config_get_privkey - Get private key for {Client,Server}Hello from .conf
 * @peer_type: IN: peer type
 * @pq_privkey: OUT: in-memory PQ private key
 * @privkey: OUT: in-memory private key
 *
 * Retrieve the PQ private key first, then the RSA private key.
 *
 * Return values:
 *   %true: private key retrieved successfully
 *   %false: private key not retrieved
 */
bool tlshd_config_get_privkey(int peer_type, gnutls_privkey_t *pq_privkey,
			      gnutls_privkey_t *privkey)
{
	__tlshd_config_get_privkey(peer_type, pq_privkey, true);
	return __tlshd_config_get_privkey(peer_type, privkey, false);
}
