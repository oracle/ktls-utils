/**
 * @file ktls.c
 * @brief Initialize a kTLS socket. In some cases initialization might
 *	  be handled by the TLS library
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
#include <string.h>
#include <errno.h>

#include <netinet/tcp.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/socket.h>
#include <gnutls/abstract.h>

#include <linux/tls.h>

#include <glib.h>

#include "tlshd.h"
#include "netlink.h"

/**
 * @brief Concatenate two NUL-terminated C strings
 * @param[in]     str1  left-hand string
 * @param[in]     str2  right-hand string
 *
 * @returns "str1" followed by "str2"
 */
static char *tlshd_string_concat(char *str1, const char *str2)
{
	size_t len = 0;
	char *result;

	if (!str1 && !str2)
		return NULL;

	if (str1)
		len += strlen(str1);
	if (str2)
		len += strlen(str2);

	result = malloc(len + 1);
	if (result) {
		result[0] = '\0';
		if (str1)
			strcat(result, str1);
		if (str2)
			strcat(result, str2);
	}

	free(str1);
	return result;
}

#ifdef HAVE_GNUTLS_TRANSPORT_IS_KTLS_ENABLED
/**
 * @brief Determine if a session is kTLS-enabled
 * @param[in]     session  An established TLS session
 * @param[in]     read     Which side of the duplex to check
 *
 * @retval  true   The session is prepared to use kTLS
 * @retval  false  The session is not prepared to use kTLS
 */
static bool tlshd_is_ktls_enabled(gnutls_session_t session, unsigned read)
{
	int ret;

	ret = gnutls_transport_is_ktls_enabled(session);
	if (ret == GNUTLS_E_UNIMPLEMENTED_FEATURE)
		return false;

	if (read) {
		if (!(ret & GNUTLS_KTLS_RECV))
			return false;
		tlshd_log_debug("Library has enabled receive kTLS for this session.");
	} else {
		if (!(ret & GNUTLS_KTLS_SEND))
			return false;
		tlshd_log_debug("Library has enabled send kTLS for this session.");
	}
	return true;
}

#else
/**
 * @brief Determine if a session is kTLS-enabled
 * @param[in]     session  An established TLS session
 * @param[in]     read     Which side of the duplex to check
 *
 * @retval  true   The session is prepared to use kTLS
 * @retval  false  The session is not prepared to use kTLS
 */
static bool tlshd_is_ktls_enabled(__attribute__ ((unused)) gnutls_session_t session,
				  __attribute__ ((unused)) unsigned read)
{
	return false;
}
#endif

/**
 * @brief Call setsockopt(3), with error logging
 * @param[in]     sock     An open socket descriptor
 * @param[in]     read     Read or write side
 * @param[in]     info     The value to set
 * @param[in]     infolen  The size of "info", in bytes
 *
 * @retval  true   The option was set successfully
 * @retval  false  The option was not set
 */
static bool tlshd_setsockopt(int sock, unsigned read, const void *info,
			     socklen_t infolen)
{
	int ret;

	ret = setsockopt(sock, SOL_TLS, read ? TLS_RX : TLS_TX, info, infolen);
	if (!ret)
		return true;

	switch (errno) {
	case EBADF:
	case ENOTSOCK:
		tlshd_log_error("The kernel's socket file descriptor is no longer valid.");
		break;
	case EINVAL:
	case ENOENT:
	case ENOPROTOOPT:
		tlshd_log_error("The kernel does not support the requested algorithm.");
		break;
	default:
		tlshd_log_perror("setsockopt");
	}
	return false;
}

#if defined(TLS_CIPHER_AES_GCM_128)
/**
 * @brief Configure TLS session for AES-GCM-128 encryption
 * @param[in]     session  An established TLS session
 * @param[in]     sock     An open socket descriptor
 * @param[in]     read     Read or write side
 *
 * @retval  true   The session was configured successfully
 * @retval  false  The session was not configured
 */
static bool tlshd_set_aes_gcm128_info(gnutls_session_t session, int sock,
				      unsigned read)
{
	struct tls12_crypto_info_aes_gcm_128 info = {
		.info.version		= TLS_1_3_VERSION,
		.info.cipher_type	= TLS_CIPHER_AES_GCM_128,
	};
	unsigned char seq_number[8];
	gnutls_datum_t cipher_key;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv;
	int ret;

	if (tlshd_is_ktls_enabled(session, read))
		return true;

	ret = gnutls_record_get_state(session, read, &mac_key, &iv,
				      &cipher_key, seq_number);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	/* TLSv1.2 generates iv in the kernel */
	if (gnutls_protocol_get_version(session) == GNUTLS_TLS1_2) {
		info.info.version = TLS_1_2_VERSION;
		memcpy(info.iv, seq_number, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	} else
		memcpy(info.iv, iv.data + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
		       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(info.salt, iv.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(info.key, cipher_key.data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(info.rec_seq, seq_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	return tlshd_setsockopt(sock, read, &info, sizeof(info));
}
#endif

#if defined(TLS_CIPHER_AES_GCM_256)
/**
 * @brief Configure TLS session for AES-GCM-256 encryption
 * @param[in]     session  An established TLS session
 * @param[in]     sock     An open socket descriptor
 * @param[in]     read     Read or write side
 *
 * @retval  true   The session was configured successfully
 * @retval  false  The session was not configured
 */
static bool tlshd_set_aes_gcm256_info(gnutls_session_t session, int sock,
				      unsigned read)
{
	struct tls12_crypto_info_aes_gcm_256 info = {
		.info.version		= TLS_1_3_VERSION,
		.info.cipher_type	= TLS_CIPHER_AES_GCM_256,
	};
	unsigned char seq_number[8];
	gnutls_datum_t cipher_key;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv;
	int ret;

	if (tlshd_is_ktls_enabled(session, read))
		return true;

	ret = gnutls_record_get_state(session, read, &mac_key, &iv,
				      &cipher_key, seq_number);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	/* TLSv1.2 generates iv in the kernel */
	if (gnutls_protocol_get_version(session) == GNUTLS_TLS1_2) {
		info.info.version = TLS_1_2_VERSION;
		memcpy(info.iv, seq_number, TLS_CIPHER_AES_GCM_256_IV_SIZE);
	} else
		memcpy(info.iv, iv.data + TLS_CIPHER_AES_GCM_256_SALT_SIZE,
		       TLS_CIPHER_AES_GCM_256_IV_SIZE);
	memcpy(info.salt, iv.data, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
	memcpy(info.key, cipher_key.data, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
	memcpy(info.rec_seq, seq_number, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

	return tlshd_setsockopt(sock, read, &info, sizeof(info));
}
#endif

#if defined(TLS_CIPHER_AES_CCM_128)
/**
 * @brief Configure TLS session for AES-CCM-128 encryption
 * @param[in]     session  An established TLS session
 * @param[in]     sock     An open socket descriptor
 * @param[in]     read     Read or write side
 *
 * @retval  true   The session was configured successfully
 * @retval  false  The session was not configured
 */
static bool tlshd_set_aes_ccm128_info(gnutls_session_t session, int sock,
				      unsigned read)
{
	struct tls12_crypto_info_aes_ccm_128 info = {
		.info.version		= TLS_1_3_VERSION,
		.info.cipher_type	= TLS_CIPHER_AES_CCM_128,
	};
	unsigned char seq_number[8];
	gnutls_datum_t cipher_key;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv;
	int ret;

	if (tlshd_is_ktls_enabled(session, read))
		return true;

	ret = gnutls_record_get_state(session, read, &mac_key, &iv,
				      &cipher_key, seq_number);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	/* TLSv1.2 generates iv in the kernel */
	if (gnutls_protocol_get_version(session) == GNUTLS_TLS1_2) {
		info.info.version = TLS_1_2_VERSION;
		memcpy(info.iv, seq_number, TLS_CIPHER_AES_CCM_128_IV_SIZE);
	} else
		memcpy(info.iv, iv.data + TLS_CIPHER_AES_CCM_128_SALT_SIZE,
		       TLS_CIPHER_AES_CCM_128_IV_SIZE);
	memcpy(info.salt, iv.data, TLS_CIPHER_AES_CCM_128_SALT_SIZE);
	memcpy(info.key, cipher_key.data, TLS_CIPHER_AES_CCM_128_KEY_SIZE);
	memcpy(info.rec_seq, seq_number, TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE);

	return tlshd_setsockopt(sock, read, &info, sizeof(info));
}
#endif

#if defined(TLS_CIPHER_CHACHA20_POLY1305)
/**
 * @brief Configure TLS session for ChaCha-Poly1305 encryption
 * @param[in]     session  An established TLS session
 * @param[in]     sock     An open socket descriptor
 * @param[in]     read     Read or write side
 *
 * @retval  true   The session was configured successfully
 * @retval  false  The session was not configured
 */
static bool tlshd_set_chacha20_poly1305_info(gnutls_session_t session, int sock,
					     unsigned read)
{
	struct tls12_crypto_info_chacha20_poly1305 info = {
		.info.version		= TLS_1_3_VERSION,
		.info.cipher_type	= TLS_CIPHER_CHACHA20_POLY1305,
	};
	unsigned char seq_number[8];
	gnutls_datum_t cipher_key;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv;
	int ret;

	if (tlshd_is_ktls_enabled(session, read))
		return true;

	ret = gnutls_record_get_state(session, read, &mac_key, &iv,
				      &cipher_key, seq_number);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}

	if (gnutls_protocol_get_version(session) == GNUTLS_TLS1_2)
		info.info.version = TLS_1_2_VERSION;

	memcpy(info.iv, iv.data, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
	memcpy(info.key, cipher_key.data, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
	memcpy(info.rec_seq, seq_number, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);

	return tlshd_setsockopt(sock, read, &info, sizeof(info));
}
#endif

/**
 * @brief Initialize a socket for use by kTLS
 * @param[in]     session  TLS session descriptor
 *
 * @returns zero on success, or a positive errno value.
 */
unsigned int tlshd_initialize_ktls(gnutls_session_t session)
{
	int sockin, sockout;

	if (setsockopt(gnutls_transport_get_int(session), SOL_TCP, TCP_ULP,
		       "tls", sizeof("tls")) == -1) {
		tlshd_log_perror("setsockopt(TLS_ULP)");
		return EIO;
	}

	gnutls_transport_get_int2(session, &sockin, &sockout);

	switch (gnutls_cipher_get(session)) {
#if defined(TLS_CIPHER_AES_GCM_128)
	case GNUTLS_CIPHER_AES_128_GCM:
		return tlshd_set_aes_gcm128_info(session, sockout, 0) &&
			tlshd_set_aes_gcm128_info(session, sockin, 1) ? 0 : EIO;
#endif
#if defined(TLS_CIPHER_AES_GCM_256)
	case GNUTLS_CIPHER_AES_256_GCM:
		return tlshd_set_aes_gcm256_info(session, sockout, 0) &&
			tlshd_set_aes_gcm256_info(session, sockin, 1) ? 0 : EIO;
#endif
#if defined(TLS_CIPHER_AES_CCM_128)
	case GNUTLS_CIPHER_AES_128_CCM:
		return tlshd_set_aes_ccm128_info(session, sockout, 0) &&
			tlshd_set_aes_ccm128_info(session, sockin, 1) ? 0 : EIO;
#endif
#if defined(TLS_CIPHER_CHACHA20_POLY1305)
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return tlshd_set_chacha20_poly1305_info(session, sockout, 0) &&
			tlshd_set_chacha20_poly1305_info(session, sockin, 1) ? 0 : EIO;
#endif
	default:
		tlshd_log_error("tlshd does not support the requested cipher.");
	}

	return EIO;
}

/**
 * @brief Concatenate a cipher name to a string
 * @param[in]     pstring  NUL-terminated C string
 * @param[in]     cipher   GnuTLS cipher number
 *
 * @retval A NUL-terminated C string; caller must free the string with free(3)
 */
static char *tlshd_cipher_string_emit(char *pstring, unsigned int cipher)
{
	switch (cipher) {
#if defined(TLS_CIPHER_CHACHA20_POLY1305)
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return tlshd_string_concat(pstring, ":+CHACHA20-POLY1305");
#endif
#if defined(TLS_CIPHER_AES_GCM_256)
	case GNUTLS_CIPHER_AES_256_GCM:
		return tlshd_string_concat(pstring, ":+AES-256-GCM");

#endif
#if defined(TLS_CIPHER_AES_GCM_128)
	case GNUTLS_CIPHER_AES_128_GCM:
		return tlshd_string_concat(pstring, ":+AES-128-GCM");
#endif
#if defined(TLS_CIPHER_AES_CCM_128)
	case GNUTLS_CIPHER_AES_128_CCM:
		return tlshd_string_concat(pstring, ":+AES-128-CCM");
#endif
	}

	return pstring;
}

static gnutls_priority_t	tlshd_gnutls_priority_x509;
static gnutls_priority_t	tlshd_gnutls_priority_psk;
static gnutls_priority_t	tlshd_gnutls_priority_psk_sha256;
static gnutls_priority_t	tlshd_gnutls_priority_psk_sha384;

/**
 * @brief Initialize GnuTLS priority caches
 * @param[in]     ciphers       Array of GnuTLS cipher numbers
 * @param[in]     cipher_count  count of elements in "ciphers"
 *
 * @retval Zero on success; a negative errno if a failure occurred.
 */
static int tlshd_gnutls_priority_init_list(const unsigned int *ciphers,
					   int cipher_count)
{
	char *pstring, *pstring_sha256, *pstring_sha384;
	const char *errpos;
	int ret, i;

	pstring = strdup("-COMP-ALL");
	if (!pstring)
		return -ENOMEM;

	/* All kernel TLS consumers require TLS v1.3 or newer. */
	pstring = tlshd_string_concat(pstring, ":-VERS-ALL:+VERS-TLS1.3:%NO_TICKETS");
	if (!pstring)
		return -ENOMEM;

	/*
	 * Handshakes must negotiate only ciphers that are supported
	 * by kTLS. The list below contains the ciphers that are
	 * common to both kTLS and GnuTLS (Linux v6.2, GnuTLS 3.8.0).
	 *
	 * The resulting list is ordered by local system priority.
	 */
	pstring = tlshd_string_concat(pstring, ":-CIPHER-ALL");
	if (!pstring)
		return -ENOMEM;
	pstring_sha256 = strdup(pstring);
	if (!pstring_sha256) {
		free(pstring);
		return -ENOMEM;
	}
	pstring_sha384 = strdup(pstring);
	if (!pstring_sha384) {
		free(pstring_sha256);
		free(pstring);
		return -ENOMEM;
	}

	for (i = 0; i < cipher_count; ++i) {
		bool skip_sha256 = false;
		bool skip_sha384 = false;

		pstring = tlshd_cipher_string_emit(pstring, ciphers[i]);
		if (!pstring) {
			free(pstring_sha256);
			free(pstring_sha384);
			return -ENOMEM;
		}
		if (ciphers[i] == GNUTLS_CIPHER_AES_256_GCM)
			skip_sha256 = true;
		if (ciphers[i] == GNUTLS_CIPHER_AES_128_GCM)
			skip_sha384 = true;
		if (ciphers[i] == GNUTLS_CIPHER_AES_128_CCM)
			skip_sha384 = true;
		if (ciphers[i] == GNUTLS_CIPHER_CHACHA20_POLY1305)
			skip_sha256 = true;
		if (!skip_sha256) {
			pstring_sha256 = tlshd_cipher_string_emit(pstring_sha256, ciphers[i]);
			if (!pstring_sha256) {
				free(pstring_sha384);
				free(pstring);
				return -ENOMEM;
			}
		}
		if (!skip_sha384) {
			pstring_sha384 = tlshd_cipher_string_emit(pstring_sha384, ciphers[i]);
			if (!pstring_sha384) {
				free(pstring_sha256);
				free(pstring);
				return -ENOMEM;
			}
		}
	}

	tlshd_log_debug("x.509 priority string: %s\n", pstring);
	ret = gnutls_priority_init2(&tlshd_gnutls_priority_x509, pstring, &errpos,
				    GNUTLS_PRIORITY_INIT_DEF_APPEND);
	if (ret != GNUTLS_E_SUCCESS) {
		free(pstring_sha256);
		free(pstring_sha384);
		free(pstring);
		tlshd_log_gnutls_error(ret);
		return -EIO;
	}
	pstring = tlshd_string_concat(pstring, ":+PSK:+DHE-PSK:+ECDHE-PSK");
	if (!pstring) {
		free(pstring_sha256);
		free(pstring_sha384);
		gnutls_priority_deinit(tlshd_gnutls_priority_x509);
		return -ENOMEM;
	}

	tlshd_log_debug("PSK priority string: %s\n", pstring);
	ret = gnutls_priority_init2(&tlshd_gnutls_priority_psk, pstring, &errpos,
				    GNUTLS_PRIORITY_INIT_DEF_APPEND);
	if (ret != GNUTLS_E_SUCCESS) {
		free(pstring_sha256);
		free(pstring_sha384);
		free(pstring);
		gnutls_priority_deinit(tlshd_gnutls_priority_x509);
		tlshd_log_gnutls_error(ret);
		return -EIO;
	}
	free(pstring);
	pstring = tlshd_string_concat(pstring_sha256, ":+DHE-PSK:+ECDHE-PSK");
	if (!pstring) {
		free(pstring_sha384);
		gnutls_priority_deinit(tlshd_gnutls_priority_psk);
		gnutls_priority_deinit(tlshd_gnutls_priority_x509);
		return -ENOMEM;
	}

	tlshd_log_debug("PSK SHA256 priority string: %s\n", pstring);
	ret = gnutls_priority_init2(&tlshd_gnutls_priority_psk_sha256,
				   pstring, &errpos,
				   GNUTLS_PRIORITY_INIT_DEF_APPEND);
	if (ret != GNUTLS_E_SUCCESS) {
		free(pstring);
		free(pstring_sha384);
		gnutls_priority_deinit(tlshd_gnutls_priority_psk);
		gnutls_priority_deinit(tlshd_gnutls_priority_x509);
		tlshd_log_gnutls_error(ret);
		return -EIO;
	}
	free(pstring);
	pstring = tlshd_string_concat(pstring_sha384, ":+DHE-PSK:+ECDHE-PSK");
	if (!pstring) {
		gnutls_priority_deinit(tlshd_gnutls_priority_psk_sha256);
		gnutls_priority_deinit(tlshd_gnutls_priority_psk);
		gnutls_priority_deinit(tlshd_gnutls_priority_x509);
		tlshd_log_gnutls_error(ret);
		return -EIO;
	}

	tlshd_log_debug("PSK SHA384 priority string: %s\n", pstring);
	ret = gnutls_priority_init2(&tlshd_gnutls_priority_psk_sha384,
				   pstring, &errpos,
				   GNUTLS_PRIORITY_INIT_DEF_APPEND);
	if (ret != GNUTLS_E_SUCCESS) {
		free(pstring);
		gnutls_priority_deinit(tlshd_gnutls_priority_psk_sha256);
		gnutls_priority_deinit(tlshd_gnutls_priority_psk);
		gnutls_priority_deinit(tlshd_gnutls_priority_x509);
		tlshd_log_gnutls_error(ret);
		return -EIO;
	}
	free(pstring);

	return 0;
}

/**
 * @brief Initialize GnuTLS priority caches
 *
 * @returns zero on success, or a negative errno value if a failure
 * occurred.
 */
int tlshd_gnutls_priority_init(void)
{
	const unsigned int *ciphers;
	gnutls_priority_t pcache;
	const char *errpos;
	int ret;

	/* Retrieve the system default priority settings */
	ret = gnutls_priority_init(&pcache, NULL, &errpos);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return -EIO;
	}

	ret = gnutls_priority_cipher_list(pcache, &ciphers);
	if (ret < 0) {
		tlshd_log_gnutls_error(ret);
		ret = -EIO;
		goto out;
	}

	ret = tlshd_gnutls_priority_init_list(ciphers, ret);

out:
	gnutls_priority_deinit(pcache);
	return ret;
}

/**
 * @brief Select GnuTLS priority cache to use for "session"
 * @param[in]     session  Session to initialize
 * @param[in]     parms    Handshake parameters
 * @param[in]     psk_len  Size of pre-shared key in bytes, or zero
 *
 * @returns GNUTLS_E_SUCCESS on success, otherwise an error code.
 */
int tlshd_gnutls_priority_set(gnutls_session_t session,
			      const struct tlshd_handshake_parms *parms,
			      unsigned int psk_len)
{
	gnutls_priority_t priority = tlshd_gnutls_priority_x509;

	if (parms->auth_mode == HANDSHAKE_AUTH_PSK) {
		if (psk_len == 32)
			priority = tlshd_gnutls_priority_psk_sha256;
		else if (psk_len == 48)
			priority = tlshd_gnutls_priority_psk_sha384;
		else
			priority = tlshd_gnutls_priority_psk;
	}

	return gnutls_priority_set(session, priority);
}

/**
 * @brief Free GnuTLS priority caches
 */
void tlshd_gnutls_priority_deinit(void)
{
	gnutls_priority_deinit(tlshd_gnutls_priority_x509);
	gnutls_priority_deinit(tlshd_gnutls_priority_psk);
	gnutls_priority_deinit(tlshd_gnutls_priority_psk_sha256);
	gnutls_priority_deinit(tlshd_gnutls_priority_psk_sha384);
}
