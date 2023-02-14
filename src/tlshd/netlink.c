/*
 * Netlink operations for tlshd
 *
 * Copyright (c) 2023 Oracle and/or its affiliates.
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
#include <sys/stat.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <linux/tls.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>

#include <glib.h>

#include "tlshd.h"

static int tlshd_nl_valid_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[HANDSHAKE_NL_ATTR_MAX + 1];
	struct tlshd_handshake_parms *parms = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	int err;

	err = nlmsg_parse(hdr, 0, tb, HANDSHAKE_NL_ATTR_MAX, NULL);
	if (err < 0) {
		tlshd_log_nl_error("nlmsg_parse", err);
		return NL_STOP;
	}

	if (tb[HANDSHAKE_NL_ATTR_MSG_STATUS]) {
		parms->status = nla_get_u32(tb[HANDSHAKE_NL_ATTR_MSG_STATUS]);
		return NL_STOP;
	}
	parms->status = HANDSHAKE_NL_STATUS_OK;

	if (tb[HANDSHAKE_NL_ATTR_SOCKFD])
		parms->sockfd = nla_get_u32(tb[HANDSHAKE_NL_ATTR_SOCKFD]);

	/* Nested TLS-specific attributes */

	err = nla_parse_nested(tb, HANDSHAKE_NL_ATTR_MAX,
			       tb[HANDSHAKE_NL_ATTR_ACCEPT_RESP], NULL);
	if (err < 0) {
		tlshd_log_nl_error("nlmsg_parse_nested", err);
		return NL_STOP;
	}

	parms->handshake_type = HANDSHAKE_NL_TLS_TYPE_UNSPEC;
	if (tb[HANDSHAKE_NL_ATTR_TLS_TYPE])
		parms->handshake_type = nla_get_u32(tb[HANDSHAKE_NL_ATTR_TLS_TYPE]);
	parms->auth_type = HANDSHAKE_NL_TLS_AUTH_UNSPEC;
	if (tb[HANDSHAKE_NL_ATTR_TLS_AUTH])
		parms->auth_type = nla_get_u32(tb[HANDSHAKE_NL_ATTR_TLS_AUTH]);
	parms->priorities = TLS_DEFAULT_PRIORITIES;
	if (tb[HANDSHAKE_NL_ATTR_TLS_PRIORITIES])
		parms->priorities = strdup(nla_get_string(tb[HANDSHAKE_NL_ATTR_TLS_PRIORITIES]));
	parms->x509_cert = HANDSHAKE_NO_CERT;
	if (tb[HANDSHAKE_NL_ATTR_TLS_X509_CERT])
		parms->x509_cert = nla_get_u32(tb[HANDSHAKE_NL_ATTR_TLS_X509_CERT]);
	parms->x509_privkey = HANDSHAKE_NO_PRIVKEY;
	if (tb[HANDSHAKE_NL_ATTR_TLS_X509_PRIVKEY])
		parms->x509_privkey = nla_get_u32(tb[HANDSHAKE_NL_ATTR_TLS_X509_PRIVKEY]);
	parms->peerid = HANDSHAKE_NO_PEERID;
	if (tb[HANDSHAKE_NL_ATTR_TLS_PSK])
		parms->peerid = nla_get_u32(tb[HANDSHAKE_NL_ATTR_TLS_PSK]);
	parms->timeout = GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;
	if (tb[HANDSHAKE_NL_ATTR_TLS_TIMEOUT])
		parms->timeout = nla_get_u32(tb[HANDSHAKE_NL_ATTR_TLS_TIMEOUT]) * 1000;

	return NL_SKIP;
}

/**
 * tlshd_nl_get_handshake_parms - Retrieve handshake parameters
 * @parms: buffer to fill in with parameters
 *
 * Returns 0 if handshake parameters were retrieved successfully.
 * Caller must free the string returned in parms->priorities with
 * free(3).
 *
 * Otherwise a negative errno is returned, and the content of
 * @parms is indeterminant.
 */
int tlshd_nl_get_handshake_parms(struct tlshd_handshake_parms *parms)
{
	struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int err, ret;

	tlshd_log_debug("Querying NETLINK_HANDSHAKE\n");
	parms->status = HANDSHAKE_NL_STATUS_SYSTEMFAULT;

	ret = -ENOMEM;
	nls = nl_socket_alloc();
	if (!nls) {
		tlshd_log_error("Failed to allocate netlink socket.");
		goto out;
	}

	ret = -ENOLINK;
	err = nl_connect(nls, NETLINK_HANDSHAKE);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_connect", err);
		goto out_sockfree;
	}

	ret = -ENOMEM;
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		tlshd_log_error("Failed to allocate netlink callback.");
		goto out_close;
	}
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, tlshd_nl_valid_handler, parms);

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_cb_put;
	}

	ret = -EIO;
	hdr = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
			HANDSHAKE_NL_MSG_ACCEPT, 0, NLM_F_REQUEST);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_msgfree;
	}

	ret = nla_put_u32(msg, HANDSHAKE_NL_ATTR_PROTOCOL,
			  HANDSHAKE_NL_PROTO_TLS_13);
	if (ret < 0) {
		tlshd_log_nl_error("nla_put protocol", err);
		goto out_msgfree;
	}

	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_msgfree;
	}

	err = nl_recvmsgs(nls, cb);
	if (err < 0)
		tlshd_log_nl_error("nl_recvmsgs", err);
	ret = 0;

out_msgfree:
	nlmsg_free(msg);
out_cb_put:
	nl_cb_put(cb);
out_close:
	nl_close(nls);
out_sockfree:
	nl_socket_free(nls);
out:
	if (parms->status != HANDSHAKE_NL_STATUS_OK) {
		tlshd_log_error("Failed to fetch handshake parameters.");
		ret = -EINVAL;
	}
	return ret;
}

/**
 * tlshd_nl_done - Indicate handshake has completed
 * @parms: buffer filled in with parameters
 *
 */
void tlshd_nl_done(struct tlshd_handshake_parms *parms)
{
	struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nlattr *args;
	struct nl_msg *msg;
	int err;

	tlshd_log_debug("Completing NETLINK_HANDSHAKE\n");

	nls = nl_socket_alloc();
	if (!nls) {
		tlshd_log_error("Failed to allocate netlink socket.");
		return;
	}

	err = nl_connect(nls, NETLINK_HANDSHAKE);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_connect", err);
		goto out_close;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_close;
	}

	hdr = nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, HANDSHAKE_NL_MSG_DONE,
			0, NLM_F_REQUEST);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_NL_ATTR_SOCKFD, parms->sockfd);
	if (err < 0) {
		tlshd_log_nl_error("nla_put sockfd", err);
		goto out_free;
	}

	args = nla_nest_start(msg, HANDSHAKE_NL_ATTR_DONE_ARGS | NLA_F_NESTED );
	if (!args) {
		tlshd_log_error("Failed to set up nested attribute.");
		goto out_free;
	}

	switch (tlshd_completion_status) {
	case 0:
		err = nla_put_u32(msg, HANDSHAKE_NL_ATTR_TLS_SESS_STATUS,
				  HANDSHAKE_NL_TLS_SESS_STATUS_OK);
		break;
	case -EACCES:
		err = nla_put_u32(msg, HANDSHAKE_NL_ATTR_TLS_SESS_STATUS,
				  HANDSHAKE_NL_TLS_SESS_STATUS_REJECTED);
		break;
	default:
		err = nla_put_u32(msg, HANDSHAKE_NL_ATTR_TLS_SESS_STATUS,
				  HANDSHAKE_NL_TLS_SESS_STATUS_FAULT);
	}
	if (err) {
		tlshd_log_nl_error("nla_put sess status", err);
		nla_nest_cancel(msg, args);
		goto out_free;
	}

	/* To do */
	err = nla_put_u32(msg, HANDSHAKE_NL_ATTR_TLS_AUTH,
			  HANDSHAKE_NL_TLS_AUTH_UNAUTH);
	if (err < 0) {
		tlshd_log_nl_error("nla_put authtype", err);
		nla_nest_cancel(msg, args);
		goto out_free;
	}
	/* To do */
	err = nla_put_u32(msg, HANDSHAKE_NL_ATTR_TLS_PEERID,
			  HANDSHAKE_NO_PEERID);
	if (err < 0) {
		tlshd_log_nl_error("nla_put peer id", err);
		nla_nest_cancel(msg, args);
		goto out_free;
	}

	err = nla_nest_end(msg, args);
	if (err < 0) {
		tlshd_log_nl_error("nla_nest_end", err);
		nla_nest_cancel(msg, args);
		goto out_free;
	}

	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_close;
	}

out_free:
	nlmsg_free(msg);
out_close:
	nl_close(nls);
	nl_socket_free(nls);
}
