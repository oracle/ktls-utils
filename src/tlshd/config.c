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

GKeyFile *tlshd_configuration;

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
	GError *error;

	tlshd_configuration = g_key_file_new();

	error = NULL;
	if (!g_key_file_load_from_file(tlshd_configuration, pathname,
				       G_KEY_FILE_KEEP_COMMENTS |
				       G_KEY_FILE_KEEP_TRANSLATIONS,
				       &error)) {
		tlshd_log_gerror("Failed to load config file", error);
		g_error_free(error);
		return false;
	}

	/*
	 * These calls return zero if the key isn't present or the
	 * specified key value is invalid.
	 */
	tlshd_debug = g_key_file_get_integer(tlshd_configuration, "main",
					     "debug", NULL);
	tlshd_library_debug = g_key_file_get_integer(tlshd_configuration,
						     "main", "libdebug", NULL);
	nl_debug = g_key_file_get_integer(tlshd_configuration, "main",
					  "nl_debug", NULL);

	return true;
}

void tlshd_config_shutdown(void)
{
	g_key_file_free(tlshd_configuration);
}

#if HAVE_LINUX_OPENAT2_H
#include <linux/openat2.h>

#ifndef SYS_openat2
#define SYS_openat2 __NR_openat2
#endif

static int tlshd_file_open(const char *pathname)
{
	static const struct open_how how = {
		.flags		= O_RDONLY,
		.resolve	= RESOLVE_NO_SYMLINKS,
	};

	return syscall(SYS_openat2, 0, pathname, &how, sizeof(how));
}
#else
static int tlshd_file_open(const char *pathname)
{
	return open(pathname, O_RDONLY);
}
#endif

/*
 * On success, caller must release buffer returned in @data by calling free(3)
 */
static bool tlshd_config_read_datum(const char *pathname, gnutls_datum_t *data)
{
	struct stat statbuf;
	void *buf;
	bool ret;
	int fd;

	ret = false;

	fd = tlshd_file_open(pathname);
	if (fd == -1) {
		tlshd_log_perror("Failed to open file");
		goto out;
	}
	if (fstat(fd, &statbuf)) {
		tlshd_log_perror("Failed to stat file");
		goto out_close;
	}
	buf = malloc(statbuf.st_size);
	if (!buf) {
		errno = ENOMEM;
		tlshd_log_perror("Failed to allocate buffer");
		goto out_close;
	}
	if (read(fd, buf, statbuf.st_size) == -1) {
		tlshd_log_perror("Failed to read file");
		free(buf);
		goto out_close;
	}
	data->data = buf;
	data->size = statbuf.st_size;
	ret = true;

out_close:
	close(fd);
out:
	return ret;
}

/**
 * tlshd_config_get_client_cert - Get cert for ClientHello from .conf
 * @cert: OUT: in-memory certificate
 *
 * Return values:
 *   %true: certificate retrieved successfully
 *   %false: certificate not retrieved
 */
bool tlshd_config_get_client_cert(gnutls_pcert_st *cert)
{
	GError *error = NULL;
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.client",
					"x509.certificate", &error);
	if (!pathname) {
		tlshd_log_gerror("Default certificate not found", error);
		g_error_free(error);
		return false;
	}

	if (!tlshd_config_read_datum(pathname, &data))
		return false;

	/* Config file supports only PEM-encoded certificates */
	ret = gnutls_pcert_import_x509_raw(cert, &data,
					   GNUTLS_X509_FMT_PEM, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	tlshd_log_debug("Retrieved x.509 certificate from %s", pathname);
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
	GError *error = NULL;
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.client",
					"x509.private_key", &error);
	if (!pathname) {
		tlshd_log_gerror("Default private key not found", error);
		g_error_free(error);
		return false;
	}

	if (!tlshd_config_read_datum(pathname, &data))
		return false;

	ret = gnutls_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(data.data);
		return false;
	}

	/* Config file supports only PEM-encoded keys */
	ret = gnutls_privkey_import_x509_raw(*privkey, &data,
					     GNUTLS_X509_FMT_PEM, NULL, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	tlshd_log_debug("Retrieved private key from %s", pathname);
	return true;
}

/**
 * tlshd_config_get_server_cert - Get cert for ServerHello from .conf
 * @cert: OUT: in-memory certificate
 *
 * Return values:
 *   %true: certificate retrieved successfully
 *   %false: certificate not retrieved
 */
bool tlshd_config_get_server_cert(gnutls_pcert_st *cert)
{
	GError *error = NULL;
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.server",
					"x509.certificate", &error);
	if (!pathname) {
		tlshd_log_gerror("Default certificate not found", error);
		g_error_free(error);
		return false;
	}

	if (!tlshd_config_read_datum(pathname, &data))
		return false;

	/* Config file supports only PEM-encoded certificates */
	ret = gnutls_pcert_import_x509_raw(cert, &data,
					   GNUTLS_X509_FMT_PEM, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	tlshd_log_debug("Retrieved x.509 certificate from %s", pathname);
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
	GError *error = NULL;
	gnutls_datum_t data;
	gchar *pathname;
	int ret;

	pathname = g_key_file_get_string(tlshd_configuration, "authenticate.server",
					"x509.private_key", &error);
	if (!pathname) {
		tlshd_log_gerror("Default private key not found", error);
		g_error_free(error);
		return false;
	}

	if (!tlshd_config_read_datum(pathname, &data))
		return false;

	ret = gnutls_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		free(data.data);
		return false;
	}

	/* Config file supports only PEM-encoded keys */
	ret = gnutls_privkey_import_x509_raw(*privkey, &data,
					     GNUTLS_X509_FMT_PEM, NULL, 0);
	free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	tlshd_log_debug("Retrieved private key from %s", pathname);
	return true;
}
