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
extern int tlshd_tls_debug;
extern unsigned int tlshd_delay_done;
extern int tlshd_stderr;

struct nl_sock;

struct tlshd_handshake_parms {
	char		*peername;
	char		*peeraddr;
	int		sockfd;
	int		ip_proto;
	uint32_t	handshake_type;
	unsigned int	timeout_ms;
	uint32_t	auth_mode;
	key_serial_t	keyring;
	key_serial_t	x509_cert;
	key_serial_t	x509_privkey;
	GArray		*peerids;
	GArray		*remote_peerids;

	unsigned int	session_status;
};

enum peer_type {
	PEER_TYPE_CLIENT,
	PEER_TYPE_SERVER,
};

/* client.c */
extern void tlshd_tls13_clienthello_handshake(struct tlshd_handshake_parms *parms);
extern void tlshd_quic_clienthello_handshake(struct tlshd_handshake_parms *parms);

/* config.c */
bool tlshd_config_init(const gchar *pathname, bool legacy);
void tlshd_config_shutdown(void);
bool tlshd_config_get_truststore(int peer_type, char **bundle);
bool tlshd_config_get_crl(int peer_type, char **result);
bool tlshd_config_get_certs(int peer_type, gnutls_pcert_st *certs,
			    unsigned int *pq_certs_len,
			    unsigned int *certs_len,
			    gnutls_pk_algorithm_t *pkalg);
bool tlshd_config_get_privkey(int peer_type, gnutls_privkey_t *pq_privkey,
			      gnutls_privkey_t *privkey);

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
				      gnutls_privkey_t *privkey);
extern bool tlshd_keyring_get_certs(key_serial_t serial, gnutls_pcert_st *certs,
				    unsigned int *certs_len);
extern key_serial_t tlshd_keyring_create_cert(gnutls_x509_crt_t cert,
					      const char *peername);
extern int tlshd_keyring_link_session(const char *keyring);

/* ktls.c */
extern unsigned int tlshd_initialize_ktls(gnutls_session_t session);
extern int tlshd_gnutls_priority_init(void);
extern int tlshd_gnutls_priority_set(gnutls_session_t session,
				     const struct tlshd_handshake_parms *parms,
				     unsigned int psk_len);
extern void tlshd_gnutls_priority_deinit(void);

/* log.c */
extern void tlshd_log_init(const char *progname);
extern void tlshd_log_shutdown(void);
extern void tlshd_log_close(void);

extern void tlshd_log_completion(struct tlshd_handshake_parms *parms);
extern void tlshd_log_debug(const char *fmt, ...);
extern void tlshd_log_notice(const char *fmt, ...);
extern void tlshd_log_error(const char *fmt, ...);
extern void tlshd_log_perror(const char *prefix);
extern void tlshd_log_gai_error(int error);

extern void tlshd_log_cert_verification_error(gnutls_session_t session);
extern void tlshd_log_gnutls_error(int error);
extern void tlshd_gnutls_log_func(int level, const char *msg);
extern void tlshd_gnutls_audit_func(gnutls_session_t session, const char *msg);

void tlshd_log_gerror(const char *msg, GError *error);
void tlshd_log_nl_error(const char *msg, int err);

/* netlink.c */
extern void tlshd_genl_dispatch(void);
extern int tlshd_genl_get_handshake_parms(struct tlshd_handshake_parms *parms);
extern void tlshd_genl_put_handshake_parms(struct tlshd_handshake_parms *parms);
extern void tlshd_genl_done(struct tlshd_handshake_parms *parms);

/* server.c */
extern void tlshd_tls13_serverhello_handshake(struct tlshd_handshake_parms *parms);
extern void tlshd_quic_serverhello_handshake(struct tlshd_handshake_parms *parms);

#ifdef HAVE_GNUTLS_QUIC
#include "quic.h"

#ifndef SOL_QUIC
#define SOL_QUIC	288
#endif
#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC	261
#endif

#define TLSHD_QUIC_MAX_DATA_LEN		4096
#define TLSHD_QUIC_MAX_ALPNS_LEN	128

struct tlshd_quic_msg {
	struct tlshd_quic_msg *next;
	uint8_t data[TLSHD_QUIC_MAX_DATA_LEN];
	uint32_t len;
	uint8_t level;
};

struct tlshd_quic_conn {
	struct tlshd_handshake_parms *parms;
	char alpns[TLSHD_QUIC_MAX_ALPNS_LEN];
	uint8_t ticket[TLSHD_QUIC_MAX_DATA_LEN];
	uint32_t ticket_len;
	uint32_t cipher;

	gnutls_session_t session;
	uint8_t recv_ticket:1;
	uint8_t completed:1;
	uint8_t cert_req:2;
	uint8_t is_serv:1;
	uint32_t errcode;
	timer_t timer;

	struct tlshd_quic_msg *send_list;
	struct tlshd_quic_msg *send_last;
	struct tlshd_quic_msg recv_msg;
};

/* quic.c */
extern int tlshd_quic_conn_create(struct tlshd_quic_conn **conn_p,
				  struct tlshd_handshake_parms *parms);
extern void tlshd_quic_conn_destroy(struct tlshd_quic_conn *conn);
extern void tlshd_quic_start_handshake(struct tlshd_quic_conn *conn);
#endif

#define TLS_DEFAULT_PSK_TYPE	"psk"
#define TLS_NO_PEERID		(0)
#define TLS_NO_CERT		(0)
#define TLS_NO_PRIVKEY		(0)
/* Max number of (chained) certs to load */
#define TLSHD_MAX_CERTS		10
