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
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <glib.h>

#include "tlshd.h"
#include "netlink.h"

/**
 * tlshd_genl_sock_open - get a connected netlink socket
 * @sock: OUT: on success, set to a connected netlink socket
 *
 * Returns zero on success or a negative errno.
 */
int tlshd_genl_sock_open(struct nl_sock **sock)
{
	struct nl_sock *nls;
	int err, ret;

	ret = -ENOMEM;
	nls = nl_socket_alloc();
	if (!nls) {
		tlshd_log_error("Failed to allocate netlink socket.");
		goto out;
	}

	ret = -ENOLINK;
	err = genl_connect(nls);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("genl_connect", err);
		nl_socket_free(nls);
		goto out;
	}

	*sock = nls;
	ret = 0;
out:
	return ret;
}

/**
 * tlshd_genl_mcgrp_join - subscribe a listener socket to a multicast group
 * @nls: socket to subscribe
 *
 * Returns zero on success or a negative errno.
 */
int tlshd_genl_mcgrp_join(struct nl_sock *nls)
{
	int err, ret, mcgrp;

	ret = -ENOLINK;
	mcgrp = genl_ctrl_resolve_grp(nls, HANDSHAKE_GENL_NAME,
				      HANDSHAKE_GENL_MCGRP_TLS_NAME);
	if (mcgrp < 0) {
		tlshd_log_nl_error("genl_ctrl_resolve_grp", mcgrp);
		goto out;
	}

	ret = -ENOENT;
	err = nl_socket_add_membership(nls, mcgrp);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_socket_add_membership", err);
		goto out;
	}

	nl_socket_disable_seq_check(nls);
	ret = 0;

out:
	return ret;
}

/**
 * tlshd_genl_sock_close - release a netlink socket
 * @sock: socket to release
 *
 */
void tlshd_genl_sock_close(struct nl_sock *nls)
{
	if (!nls)
		return;

	nl_close(nls);
	nl_socket_free(nls);
}

static const struct nla_policy
tlshd_genl_policy[HANDSHAKE_GENL_ATTR_MAX + 1] = {
	[HANDSHAKE_GENL_ATTR_MSG_STATUS]	= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_SESS_STATUS]	= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_SOCKFD]		= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_PROTOCOL]		= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_ACCEPT]		= { .type = NLA_NESTED, },
	[HANDSHAKE_GENL_ATTR_DONE]		= { .type = NLA_NESTED, },
};

static const struct nla_policy
tlshd_genl_tls_accept_policy[HANDSHAKE_GENL_ATTR_TLS_ACCEPT_MAX + 1] = {
	[HANDSHAKE_GENL_ATTR_TLS_TYPE]		= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_TLS_AUTH]		= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_TLS_PRIORITIES]	= { .type = NLA_NUL_STRING, },
	[HANDSHAKE_GENL_ATTR_TLS_X509_CERT]	= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_TLS_X509_PRIVKEY]	= { .type = NLA_U32, },
	[HANDSHAKE_GENL_ATTR_TLS_PSK]		= { .type = NLA_U32, },
};

static int tlshd_genl_valid_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[HANDSHAKE_GENL_ATTR_MAX + 1];
	struct nlattr *resp[HANDSHAKE_GENL_ATTR_TLS_ACCEPT_MAX + 1];
	struct tlshd_handshake_parms *parms = arg;
	int err;

	err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, HANDSHAKE_GENL_ATTR_MAX,
			    (struct nla_policy *)tlshd_genl_policy);
	if (err < 0) {
		tlshd_log_nl_error("genlmsg_parse", err);
		return NL_STOP;
	}

	if (tb[HANDSHAKE_GENL_ATTR_MSG_STATUS]) {
		parms->msg_status = nla_get_u32(tb[HANDSHAKE_GENL_ATTR_MSG_STATUS]);
		return NL_STOP;
	}
	parms->msg_status = 0;

	if (tb[HANDSHAKE_GENL_ATTR_SOCKFD])
		parms->sockfd = nla_get_u32(tb[HANDSHAKE_GENL_ATTR_SOCKFD]);

	/* Nested TLS-specific attributes */

	err = nla_parse_nested(resp, HANDSHAKE_GENL_ATTR_TLS_ACCEPT_MAX,
			       tb[HANDSHAKE_GENL_ATTR_ACCEPT],
			       (struct nla_policy *)tlshd_genl_tls_accept_policy);
	if (err < 0) {
		tlshd_log_nl_error("nla_parse_nested", err);
		return NL_STOP;
	}

	parms->handshake_type = HANDSHAKE_GENL_TLS_TYPE_UNSPEC;
	if (resp[HANDSHAKE_GENL_ATTR_TLS_TYPE])
		parms->handshake_type = nla_get_u32(resp[HANDSHAKE_GENL_ATTR_TLS_TYPE]);
	parms->auth_type = HANDSHAKE_GENL_TLS_AUTH_UNSPEC;
	if (resp[HANDSHAKE_GENL_ATTR_TLS_AUTH])
		parms->auth_type = nla_get_u32(resp[HANDSHAKE_GENL_ATTR_TLS_AUTH]);
	parms->priorities = TLS_DEFAULT_PRIORITIES;
	if (resp[HANDSHAKE_GENL_ATTR_TLS_PRIORITIES])
		parms->priorities =
			strdup(nla_get_string(resp[HANDSHAKE_GENL_ATTR_TLS_PRIORITIES]));
	parms->x509_cert = TLS_NO_CERT;
	if (resp[HANDSHAKE_GENL_ATTR_TLS_X509_CERT])
		parms->x509_cert = nla_get_u32(resp[HANDSHAKE_GENL_ATTR_TLS_X509_CERT]);
	parms->x509_privkey = TLS_NO_PRIVKEY;
	if (resp[HANDSHAKE_GENL_ATTR_TLS_X509_PRIVKEY])
		parms->x509_privkey =
			nla_get_u32(resp[HANDSHAKE_GENL_ATTR_TLS_X509_PRIVKEY]);
	parms->peerid = TLS_NO_PEERID;
	if (resp[HANDSHAKE_GENL_ATTR_TLS_PSK])
		parms->peerid = nla_get_u32(resp[HANDSHAKE_GENL_ATTR_TLS_PSK]);

	return NL_SKIP;
}

/**
 * tlshd_genl_get_handshake_parms - Retrieve handshake parameters
 * @parms: buffer to fill in with parameters
 *
 * Returns 0 if handshake parameters were retrieved successfully.
 * Caller must free the string returned in parms->priorities with
 * free(3).
 *
 * Otherwise a negative errno is returned, and the content of
 * @parms is indeterminant.
 */
int tlshd_genl_get_handshake_parms(struct tlshd_handshake_parms *parms)
{
	int family_id, err, ret;
	struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nl_msg *msg;
	struct nl_cb *cb;

	tlshd_log_debug("Querying the handshake service\n");
	parms->msg_status = -EIO;

	ret = tlshd_genl_sock_open(&nls);
	if (ret)
		return ret;

	ret = -ESRCH;
	family_id = genl_ctrl_resolve(nls, HANDSHAKE_GENL_NAME);
	if (family_id < 0) {
		tlshd_log_error("Failed to resolve netlink service.");
		goto out_close;
	}

	ret = -ENOMEM;
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		tlshd_log_error("Failed to allocate netlink callback.");
		goto out_close;
	}
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, tlshd_genl_valid_handler, parms);

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_cb_put;
	}

	ret = -EIO;
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
			  0, 0, HANDSHAKE_GENL_CMD_ACCEPT, 0);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_msgfree;
	}

	err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_PROTOCOL,
			  HANDSHAKE_GENL_PROTO_TLS);
	if (err < 0) {
		tlshd_log_nl_error("nla_put protocol", err);
		goto out_msgfree;
	}

	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_msgfree;
	}

	ret = -EINVAL;
	err = nl_recvmsgs(nls, cb);
	if (err < 0) {
		tlshd_log_nl_error("nl_recvmsgs", err);
		goto out_msgfree;
	}

	ret = 0;

out_msgfree:
	nlmsg_free(msg);
out_cb_put:
	nl_cb_put(cb);
out_close:
	tlshd_genl_sock_close(nls);
	return ret;
}

/**
 * tlshd_genl_done_status - Indicate handshake has failed
 * @parms: buffer filled in with parameters
 *
 */
void tlshd_genl_done_status(struct tlshd_handshake_parms *parms)
{
	struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nlattr *args;
	struct nl_msg *msg;
	int family_id, err;

	err = tlshd_genl_sock_open(&nls);
	if (err)
		return;

	family_id = genl_ctrl_resolve(nls, HANDSHAKE_GENL_NAME);
	if (family_id < 0) {
		tlshd_log_nl_error("genl_ctrl_resolve", err);
		goto out_close;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_close;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
			  0, 0, HANDSHAKE_GENL_CMD_DONE, 0);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_SOCKFD, parms->sockfd);
	if (err < 0) {
		tlshd_log_nl_error("nla_put sockfd", err);
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_SESS_STATUS,
			  parms->session_status);
	if (err) {
		tlshd_log_nl_error("nla_put sess_status", err);
		goto out_free;
	}

	if (parms->session_peerid == TLS_NO_PEERID)
		goto sendit;

	args = nla_nest_start(msg, HANDSHAKE_GENL_ATTR_DONE);
	if (!args) {
		tlshd_log_error("Failed to set up nested attribute.");
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_TLS_REMOTE_PEERID,
			  parms->session_peerid);
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

sendit:
	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_free;
	}

out_free:
	nlmsg_free(msg);
out_close:
	tlshd_genl_sock_close(nls);
}

/**
 * tlshd_genl_done - Indicate anon handshake has completed successfully
 * @parms: buffer filled in with parameters
 *
 */
void tlshd_genl_done(struct tlshd_handshake_parms *parms)
{
	struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nlattr *args;
	struct nl_msg *msg;
	int family_id, err;

	err = tlshd_genl_sock_open(&nls);
	if (err)
		return;

	family_id = genl_ctrl_resolve(nls, HANDSHAKE_GENL_NAME);
	if (family_id < 0) {
		tlshd_log_nl_error("genl_ctrl_resolve", err);
		goto out_close;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_close;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
			  0, 0, HANDSHAKE_GENL_CMD_DONE, 0);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_SOCKFD, parms->sockfd);
	if (err < 0) {
		tlshd_log_nl_error("nla_put sockfd", err);
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_SESS_STATUS,
			  parms->session_status);
	if (err) {
		tlshd_log_nl_error("nla_put sess_status", err);
		goto out_free;
	}

	if (parms->session_peerid == TLS_NO_PEERID)
		goto sendit;

	args = nla_nest_start(msg, HANDSHAKE_GENL_ATTR_DONE);
	if (!args) {
		tlshd_log_error("Failed to set up nested attribute.");
		goto out_free;
	}

	if (parms->session_peerid != TLS_NO_PEERID) {
		err = nla_put_u32(msg, HANDSHAKE_GENL_ATTR_TLS_REMOTE_PEERID,
				  parms->session_peerid);
		if (err < 0) {
			tlshd_log_nl_error("nla_put peer id", err);
			nla_nest_cancel(msg, args);
			goto out_free;
		}
	}

	err = nla_nest_end(msg, args);
	if (err < 0) {
		tlshd_log_nl_error("nla_nest_end", err);
		nla_nest_cancel(msg, args);
		goto out_free;
	}

sendit:
	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_free;
	}

out_free:
	nlmsg_free(msg);
out_close:
	tlshd_genl_sock_close(nls);
}
