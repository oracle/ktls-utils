// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is the userspace handshake part for the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <gnutls/crypto.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/tls.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include "quic.h"

#define MAX_BUFLEN	4096

struct quic_buf {
	uint32_t buflen;
	uint8_t buf[MAX_BUFLEN];
};

struct quic_frame {
	struct quic_frame *next;
	struct quic_buf data;
	uint8_t level;
};

struct quic_data {
	uint8_t data[144];
	uint32_t datalen;
};

struct quic_conn {
	struct quic_handshake_parms *parms;
	struct quic_data priority;
	struct quic_data alpn;
	uint32_t cipher;
	int sockfd;

	gnutls_session_t session;
	struct quic_buf ticket;
	uint8_t recv_ticket:1;
	uint8_t completed:1;
	uint8_t cert_req:2;
	uint8_t is_serv:1;
	uint8_t errcode;
	timer_t timer;

	struct quic_frame *send_list;
	struct quic_frame *send_last;
	struct quic_frame frame;
};

extern quic_log_func pr_error;
extern quic_log_func pr_warn;
extern quic_log_func pr_debug;

int quic_crypto_read_write_crypto_data(struct quic_conn *conn, uint8_t encryption_level,
				       const uint8_t *data, size_t datalen);
int quic_crypto_client_set_x509_session(struct quic_conn *conn);
int quic_crypto_server_set_x509_session(struct quic_conn *conn);
int quic_crypto_client_set_psk_session(struct quic_conn *conn);
int quic_crypto_server_set_psk_session(struct quic_conn *conn);
