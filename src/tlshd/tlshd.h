/*
 * Generic definitions and forward declarations for tlshd.
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

#include <linux/netlink.h>

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))

extern int tlshd_debug;
extern int tlshd_library_debug;
extern int tlshd_stderr;
extern GKeyFile *tlshd_configuration;

struct nl_sock;

struct tlshd_handshake_parms {
	char		*peername;
	int		sockfd;
	int		protocol;
	int		handshake_type;
	int		auth_type;
	char		*priorities;
	key_serial_t	x509_cert;
	key_serial_t	x509_privkey;
	key_serial_t	peerid;
	int		msg_status;

	int		session_status;
	key_serial_t	session_peerid;
};

/* client.c */
extern void tlshd_clienthello_handshake(struct tlshd_handshake_parms *parms);

/* config.c */
bool tlshd_config_init(const gchar *pathname);
void tlshd_config_shutdown(void);
bool tlshd_config_get_client_cert(gnutls_pcert_st *cert);
bool tlshd_config_get_client_privkey(gnutls_privkey_t *privkey);
bool tlshd_config_get_server_cert(gnutls_pcert_st *cert);
bool tlshd_config_get_server_privkey(gnutls_privkey_t *privkey);

/* handshake.c */
extern void tlshd_start_tls_handshake(gnutls_session_t session,
				      struct tlshd_handshake_parms *parms);
extern void tlshd_service_socket(void);

/* keyring.c */
extern bool tlshd_keyring_get_psk_username(key_serial_t serial,
					   char **username);
extern bool tlshd_keyring_get_psk_key(key_serial_t serial,
				      gnutls_datum_t *key);
extern bool tlshd_keyring_get_privkey(key_serial_t serial,
				      gnutls_privkey_t privkey);
extern bool tlshd_keyring_get_cert(key_serial_t serial, gnutls_pcert_st *cert);
extern key_serial_t tlshd_keyring_create_cert(gnutls_x509_crt_t cert,
					      const char *peername);

/* ktls.c */
extern int tlshd_initialize_ktls(gnutls_session_t session);

/* log.c */
extern void tlshd_log_init(const char *progname);
extern void tlshd_log_shutdown(void);
extern void tlshd_log_close(void);

extern void tlshd_log_success(const char *hostname,
			      const struct sockaddr *sap, socklen_t salen);
extern void tlshd_log_failure(const char *hostname,
			      const struct sockaddr *sap, socklen_t salen);

void tlshd_log_debug(const char *fmt, ...);
extern void tlshd_log_error(const char *msg);
extern void tlshd_log_perror(const char *prefix);
extern void tlshd_log_gai_error(int error);

extern void tlshd_log_cert_verification_error(gnutls_session_t session);
extern void tlshd_log_gnutls_error(int error);
extern void tlshd_gnutls_log_func(int level, const char *msg);
extern void tlshd_gnutls_audit_func(gnutls_session_t session, const char *msg);

void tlshd_log_gerror(const char *msg, GError *error);
void tlshd_log_nl_error(const char *msg, int err);

/* netlink.c */
extern int tlshd_genl_sock_open(struct nl_sock **sock);
extern int tlshd_genl_mcgrp_join(struct nl_sock *nls);
extern void tlshd_genl_sock_close(struct nl_sock *nls);
extern int tlshd_genl_get_handshake_parms(struct tlshd_handshake_parms *parms);
extern void tlshd_genl_done_status(struct tlshd_handshake_parms *parms);
extern void tlshd_genl_done(struct tlshd_handshake_parms *parms);

#define TLS_DEFAULT_PRIORITIES	(NULL)
#define TLS_NO_PEERID		(0)
#define TLS_NO_CERT		(0)
#define TLS_NO_PRIVKEY		(0)
