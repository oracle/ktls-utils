/**
 * @file dane.c
 * @brief DANE server authentication for client-side handshakes
 *
 * @copyright
 * Copyright (c) 2026 Oracle and/or its affiliates.
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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/dane.h>

#include <unbound.h>

#include <glib.h>

#include "tlshd.h"
#include "netlink.h"

/** @name DNS protocol constants */
/*@{*/
#define TLSHD_DNS_CLASS_IN		1
#define TLSHD_DNS_TYPE_A		1
#define TLSHD_DNS_TYPE_AAAA		28
#define TLSHD_DNS_TYPE_TLSA		52
#define TLSHD_DNS_RCODE_NOERROR		0
#define TLSHD_DNS_RCODE_NXDOMAIN	3
#define TLSHD_DNS_MAX_NAME		253
#define TLSHD_DNS_MAX_LABEL		63
/*@}*/

/** @name TLSA RDATA constants (RFC 6698 Section 2.1) */
/*@{*/
#define TLSHD_TLSA_USAGE_DANE_EE	3
#define TLSHD_TLSA_SELECTOR_CERT	0
#define TLSHD_TLSA_SELECTOR_SPKI	1
#define TLSHD_TLSA_MATCH_FULL		0
#define TLSHD_TLSA_MATCH_SHA256		1
#define TLSHD_TLSA_MATCH_SHA512		2
#define TLSHD_TLSA_SHA256_LEN		32
#define TLSHD_TLSA_SHA512_LEN		64
#define TLSHD_TLSA_RDATA_MIN		4
/*@}*/

/**
 * @var tlshd_dane_ta_files
 * Ordered list of DNSSEC root trust anchor files to try when the
 * config file names none. tlshd only reads an anchor; RFC 5011
 * rollover is the job of unbound-anchor(8) or its equivalent.
 */
static const char *tlshd_dane_ta_files[] = {
	"/var/lib/unbound/root.key",
	"/usr/share/dns/root.key",
	"/etc/unbound/root.key",
	"/etc/dnssec-trust-anchors.d/root.key",
	"/etc/trusted-key.key",
	NULL
};

/**
 * @struct tlshd_dane_record
 * @brief One TLSA record that survived usability filtering
 */
struct tlshd_dane_record {
	unsigned int	index;		/**< Index into the ub_result arrays */
	unsigned int	usage;		/**< Certificate usage */
	unsigned int	selector;	/**< Selector */
	unsigned int	match;		/**< Matching type */
};

/**
 * @struct tlshd_dane_result
 * @brief Retained result of one DANE evaluation
 *
 * Built before the ClientHello so that the selected TLSA base domain
 * can become the SNI value, then consumed by the certificate
 * verification callback, which performs no DNS of its own.
 */
struct tlshd_dane_result {
	enum tlshd_dane_mode	mode;		/**< Policy in effect */
	const char		*mode_source;	/**< Where the policy came from */
	enum tlshd_dane_outcome	outcome;	/**< Evaluation class */
	char			*reason;	/**< Diagnostic detail */
	char			*refname;	/**< Normalized reference name */
	char			*base_domain;	/**< Selected TLSA base domain */
	unsigned short		port;		/**< Port in the owner name */
	int			ip_proto;	/**< Transport in the owner name */

	/*
	 * dane_raw_tlsa() does not copy the RDATA it is handed. The
	 * ub_result that owns it stays alive until this object is
	 * released, after the handshake has concluded.
	 */
	struct ub_result	*tlsa;		/**< Owns the raw RDATA */
	struct tlshd_dane_record *records;	/**< Usable records */
	unsigned int		nrecords;	/**< Count of usable records */

	bool			dane_auth;	/**< Authenticated via DANE-EE */
	bool			pkix_auth;	/**< Authenticated via PKIX */
	bool			unauth;		/**< No authentication, as requested */
	bool			resumed;	/**< Resumed an earlier session */
	bool			matched;	/**< A TLSA record matched */
	struct tlshd_dane_record match;		/**< The record that matched */
	bool			audited;	/**< Audit event already emitted */
};

/**
 * @brief Render an outcome class for the audit record
 * @param[in]     outcome  Outcome to render
 *
 * @returns a static string
 */
static const char *tlshd_dane_outcome_name(enum tlshd_dane_outcome outcome)
{
	switch (outcome) {
	case TLSHD_DANE_SECURE_USABLE:
		return "SECURE_USABLE";
	case TLSHD_DANE_SECURE_UNUSABLE:
		return "SECURE_UNUSABLE";
	case TLSHD_DANE_SECURE_ABSENT:
		return "SECURE_ABSENT";
	case TLSHD_DANE_INSECURE:
		return "INSECURE";
	case TLSHD_DANE_ERROR:
		return "ERROR";
	case TLSHD_DANE_NOT_APPLICABLE:
		return "NOT_APPLICABLE";
	}
	return "UNKNOWN";
}

/**
 * @brief Render a policy mode for the audit record
 * @param[in]     mode  Mode to render
 *
 * @returns a static string
 */
static const char *tlshd_dane_mode_name(enum tlshd_dane_mode mode)
{
	switch (mode) {
	case TLSHD_DANE_MODE_OFF:
		return "off";
	case TLSHD_DANE_MODE_OPPORTUNISTIC:
		return "opportunistic";
	case TLSHD_DANE_MODE_REQUIRE:
		return "require";
	}
	return "unknown";
}

/**
 * @brief Render a transport protocol as a TLSA owner name label
 * @param[in]     ip_proto  Transport protocol number
 *
 * @returns a static string, or NULL if DANE does not cover the transport
 */
static const char *tlshd_dane_proto_label(int ip_proto)
{
	switch (ip_proto) {
	case IPPROTO_TCP:
		return "tcp";
	default:
		return NULL;
	}
}

/**
 * @brief Attach a diagnostic reason to an evaluation
 * @param[in,out] res     Result object to update
 * @param[in]     fmt     printf-style format string
 */
static void tlshd_dane_set_reason(struct tlshd_dane_result *res,
				  const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

static void tlshd_dane_set_reason(struct tlshd_dane_result *res,
				  const char *fmt, ...)
{
	va_list args;

	g_free(res->reason);
	va_start(args, fmt);
	res->reason = g_strdup_vprintf(fmt, args);
	va_end(args);
}

/**
 * @brief Test whether a reference name is an IP address literal
 * @param[in]     name  Candidate reference name
 *
 * @retval true   The name is an address literal
 * @retval false  The name may be a DNS name
 */
static bool tlshd_dane_is_ip_literal(const char *name)
{
	struct in6_addr a6;
	struct in_addr a4;
	bool literal = false;
	char *copy, *zone;

	if (name[0] == '[')
		return true;
	if (inet_pton(AF_INET, name, &a4) == 1)
		return true;
	if (inet_pton(AF_INET6, name, &a6) == 1)
		return true;

	/* A scoped literal such as fe80::1%eth0 is still a literal. */
	copy = g_strdup(name);
	zone = strchr(copy, '%');
	if (zone) {
		*zone = '\0';
		literal = inet_pton(AF_INET6, copy, &a6) == 1;
	}
	g_free(copy);
	return literal;
}

/**
 * @brief Lower-case a DNS name and remove any trailing dot
 * @param[in]     name  Name in presentation form
 *
 * @returns a newly allocated string. Caller must release it using
 * g_free().
 */
static char *tlshd_dane_canonicalize(const char *name)
{
	char *copy, *p;
	size_t len;

	copy = g_strdup(name);
	len = strlen(copy);
	if (len > 1 && copy[len - 1] == '.')
		copy[len - 1] = '\0';
	for (p = copy; *p; p++)
		*p = g_ascii_tolower(*p);
	return copy;
}

/**
 * @brief Apply the reference name input contract
 * @param[in]     name   Reference name as supplied by the kernel
 * @param[in]     port   Port number that goes in the owner name
 * @param[in]     proto  Transport label that goes in the owner name
 * @param[out]    why    Reason the name was rejected
 *
 * Rejects address literals, converts internationalized names to
 * A-label form, normalizes ASCII case, and enforces the DNS length
 * limits on the full TLSA owner name, port and transport labels
 * included.
 *
 * @returns the normalized name, or NULL when DANE cannot apply to the
 * name. Caller must release both the name and the reason using
 * g_free().
 */
static char *tlshd_dane_normalize_name(const char *name, unsigned short port,
				       const char *proto, char **why)
{
	unsigned int labels = 1, label_len = 0;
	char *work, *p, prefix[32];
	size_t len, plen;
	bool ascii;

	*why = NULL;
	if (!name || !*name) {
		*why = g_strdup("no reference name");
		return NULL;
	}

	work = g_strdup(name);
	len = strlen(work);
	if (work[len - 1] == '.')
		work[--len] = '\0';
	if (!len) {
		*why = g_strdup("reference name is the root");
		goto out_reject;
	}

	/* RFC 7671 Section 5.1: an IP literal has no TLSA binding. */
	if (tlshd_dane_is_ip_literal(work)) {
		*why = g_strdup("reference name is an IP address literal");
		goto out_reject;
	}

	ascii = true;
	for (p = work; *p; p++)
		if ((unsigned char)*p > 0x7f)
			ascii = false;
	if (!ascii) {
#ifdef HAVE_GNUTLS_IDNA_MAP
		gnutls_datum_t alabel;
		int ret;

		ret = gnutls_idna_map(work, len, &alabel, 0);
		if (ret != GNUTLS_E_SUCCESS) {
			*why = g_strdup_printf("IDNA conversion failed: %s",
					       gnutls_strerror(ret));
			goto out_reject;
		}
		g_free(work);
		work = g_strdup((const char *)alabel.data);
		gnutls_free(alabel.data);
		len = strlen(work);
#else
		*why = g_strdup("internationalized name and no IDNA support");
		goto out_reject;
#endif
	}

	/* An owner name that overflows would fail the lookup as an ERROR. */
	plen = snprintf(prefix, sizeof(prefix), "_%u._%s.", port, proto);
	if (plen + len > TLSHD_DNS_MAX_NAME) {
		*why = g_strdup_printf("TLSA owner name would be %zu octets",
				       plen + len);
		goto out_reject;
	}

	for (p = work; *p; p++) {
		unsigned char c = (unsigned char)*p;

		if (c == '.') {
			if (!label_len) {
				*why = g_strdup("reference name has an empty label");
				goto out_reject;
			}
			label_len = 0;
			labels++;
			continue;
		}
		if (++label_len > TLSHD_DNS_MAX_LABEL) {
			*why = g_strdup("reference name has an oversized label");
			goto out_reject;
		}
		if (!g_ascii_isalnum(c) && c != '-' && c != '_') {
			*why = g_strdup("reference name has an invalid character");
			goto out_reject;
		}
		*p = g_ascii_tolower(c);
	}
	if (!label_len) {
		*why = g_strdup("reference name has an empty label");
		goto out_reject;
	}
	if (labels < 2) {
		*why = g_strdup("reference name is not fully qualified");
		goto out_reject;
	}

	return work;

out_reject:
	g_free(work);
	return NULL;
}

/**
 * @brief Create and configure a DNSSEC-validating resolver context
 * @param[out]    why  Reason the context could not be created
 *
 * Call only from the per-request child: a libunbound context holds
 * sockets and threads and cannot be assumed fork-safe.
 *
 * @returns a resolver context, or NULL when no resolver or trust
 * anchor could be configured. The caller must treat NULL as an ERROR
 * outcome, never as INSECURE. Caller must release the context using
 * ub_ctx_delete() and the reason using g_free().
 */
static struct ub_ctx *tlshd_dane_resolver(char **why)
{
	gchar *anchor, **resolvers = NULL;
	struct ub_ctx *ctx;
	gsize i, count = 0;
	int ret;

	*why = NULL;
	ctx = ub_ctx_create();
	if (!ctx) {
		*why = g_strdup("failed to create a resolver context");
		return NULL;
	}
	ub_ctx_debuglevel(ctx, 0);

	resolvers = tlshd_config_get_dane_resolvers(&count);
	if (resolvers && count) {
		for (i = 0; i < count; i++) {
			ret = ub_ctx_set_fwd(ctx, resolvers[i]);
			if (ret) {
				*why = g_strdup_printf("resolver %s: %s",
						       resolvers[i],
						       ub_strerror(ret));
				goto out_fail;
			}
		}
	} else {
		ret = ub_ctx_resolvconf(ctx, NULL);
		if (ret) {
			*why = g_strdup_printf("resolv.conf: %s",
					       ub_strerror(ret));
			goto out_fail;
		}
	}

	anchor = tlshd_config_get_dane_trust_anchor();
	if (anchor) {
		ret = ub_ctx_add_ta_file(ctx, anchor);
		if (ret) {
			*why = g_strdup_printf("trust anchor %s: %s", anchor,
					       ub_strerror(ret));
			g_free(anchor);
			goto out_fail;
		}
		g_free(anchor);
	} else {
		const char *found = NULL;

		for (i = 0; tlshd_dane_ta_files[i]; i++) {
			if (access(tlshd_dane_ta_files[i], R_OK))
				continue;
			ret = ub_ctx_add_ta_file(ctx, tlshd_dane_ta_files[i]);
			if (ret) {
				*why = g_strdup_printf("trust anchor %s: %s",
						       tlshd_dane_ta_files[i],
						       ub_strerror(ret));
				goto out_fail;
			}
			found = tlshd_dane_ta_files[i];
			break;
		}
		if (!found) {
			*why = g_strdup("no DNSSEC trust anchor file found");
			goto out_fail;
		}
		tlshd_log_debug("DANE: using trust anchor %s", found);
	}

	g_strfreev(resolvers);
	return ctx;

out_fail:
	g_strfreev(resolvers);
	ub_ctx_delete(ctx);
	return NULL;
}

/**
 * @brief Determine the securely CNAME-expanded name, if there is one
 * @param[in]     ctx       Resolver context
 * @param[in,out] res       Result object to update
 * @param[out]    expanded  Expanded name, or NULL when there is none
 *
 * A CNAME chain yields an expansion only when every link validated
 * and every address family that answered agrees on the canonical
 * name. Otherwise the reference name remains the only candidate.
 *
 * @retval true   Resolution completed; caller must release the
 *		  expanded name using g_free()
 * @retval false  A lookup failed or validated as bogus, which is an
 *		  ERROR for the whole evaluation (Section 7.3 of
 *		  draft-cel-nfsv4-rpc-tls-dane); the reason is recorded
 */
static bool tlshd_dane_expanded_name(struct ub_ctx *ctx,
				     struct tlshd_dane_result *res,
				     char **expanded)
{
	static const int families[] = { TLSHD_DNS_TYPE_A, TLSHD_DNS_TYPE_AAAA };
	bool participated = false, divergent = false;
	char *qname, *found = NULL;
	unsigned int i;

	*expanded = NULL;
	qname = g_strdup_printf("%s.", res->refname);
	for (i = 0; i < ARRAY_SIZE(families); i++) {
		struct ub_result *r = NULL;
		char *canon;
		int ret;

		/*
		 * A failed or bogus lookup is within an attacker's reach.
		 * Treating it as "no expansion" would let the attacker
		 * drop the expanded name from the candidate list.
		 */
		ret = ub_resolve(ctx, qname, families[i],
				 TLSHD_DNS_CLASS_IN, &r);
		if (ret || !r) {
			ub_resolve_free(r);
			tlshd_dane_set_reason(res, "address lookup failed: %s",
					      ub_strerror(ret));
			goto out_error;
		}
		if (r->bogus) {
			tlshd_dane_set_reason(res,
					      "address lookup is bogus: %s",
					      r->why_bogus ? r->why_bogus :
					      "no detail");
			ub_resolve_free(r);
			goto out_error;
		}
		if (r->rcode != TLSHD_DNS_RCODE_NOERROR &&
		    r->rcode != TLSHD_DNS_RCODE_NXDOMAIN) {
			tlshd_dane_set_reason(res, "address lookup rcode %d",
					      r->rcode);
			ub_resolve_free(r);
			goto out_error;
		}
		if (!r->havedata) {
			ub_resolve_free(r);
			continue;
		}
		if (!r->secure) {
			/* An unvalidated answer disqualifies expansion. */
			ub_resolve_free(r);
			divergent = true;
			break;
		}

		canon = tlshd_dane_canonicalize(r->canonname ? r->canonname :
						res->refname);
		ub_resolve_free(r);
		if (!participated) {
			found = canon;
			participated = true;
			continue;
		}
		if (strcmp(found, canon)) {
			g_free(canon);
			divergent = true;
			break;
		}
		g_free(canon);
	}
	g_free(qname);

	if (divergent || !participated || !strcmp(found, res->refname)) {
		g_free(found);
		return true;
	}

	/*
	 * The canonical name comes from the zone and can push the owner
	 * name past the limit the reference name was screened for. It
	 * validated, so an attacker cannot use it to suppress the
	 * expansion; dropping it leaves the refname candidate in play.
	 */
	if ((size_t)snprintf(NULL, 0, "_%u._%s.", res->port,
			     tlshd_dane_proto_label(res->ip_proto)) +
	    strlen(found) > TLSHD_DNS_MAX_NAME) {
		g_free(found);
		return true;
	}
	*expanded = found;
	return true;

out_error:
	g_free(qname);
	g_free(found);
	return false;
}

/**
 * @brief Select the TLSA records this implementation can authenticate with
 * @param[in,out] res  Result object holding the validated RRset
 *
 * Retains DANE-EE records with a supported selector and, per RFC 7671
 * Section 9, for each selector only Full(0) records and records of
 * the strongest supported matching type. Runs before any matching so
 * that an RRset this build cannot use stays distinguishable from one
 * that does not match the peer.
 */
static void tlshd_dane_select_records(struct tlshd_dane_result *res)
{
	unsigned int strongest[2] = { 0, 0 };
	struct ub_result *r = res->tlsa;
	unsigned int i, n = 0;

	for (i = 0; r->data[i]; i++)
		n++;
	if (!n)
		return;
	res->records = g_new0(struct tlshd_dane_record, n);

	for (i = 0; i < n; i++) {
		const unsigned char *rdata = (const unsigned char *)r->data[i];
		unsigned int usage, selector, match;
		int alen = r->len[i] - 3;

		if (r->len[i] < TLSHD_TLSA_RDATA_MIN)
			continue;
		usage = rdata[0];
		selector = rdata[1];
		match = rdata[2];

		/* DANE-EE(3) only in this round. */
		if (usage != TLSHD_TLSA_USAGE_DANE_EE)
			continue;
		if (selector != TLSHD_TLSA_SELECTOR_CERT &&
		    selector != TLSHD_TLSA_SELECTOR_SPKI)
			continue;
		switch (match) {
		case TLSHD_TLSA_MATCH_FULL:
			break;
		case TLSHD_TLSA_MATCH_SHA256:
			if (alen != TLSHD_TLSA_SHA256_LEN)
				continue;
			break;
		case TLSHD_TLSA_MATCH_SHA512:
			if (alen != TLSHD_TLSA_SHA512_LEN)
				continue;
			break;
		default:
			continue;
		}

		res->records[res->nrecords].index = i;
		res->records[res->nrecords].usage = usage;
		res->records[res->nrecords].selector = selector;
		res->records[res->nrecords].match = match;
		res->nrecords++;

		if (match > strongest[selector])
			strongest[selector] = match;
	}

	/*
	 * Only supported, well-formed records reached the tally above,
	 * so an unsupported matching type cannot suppress a supported one.
	 */
	for (i = 0, n = 0; i < res->nrecords; i++) {
		struct tlshd_dane_record *rec = &res->records[i];

		if (rec->match != TLSHD_TLSA_MATCH_FULL &&
		    rec->match != strongest[rec->selector])
			continue;
		res->records[n++] = *rec;
	}
	res->nrecords = n;
}

/**
 * @brief Evaluate the TLSA RRset at one candidate base domain
 * @param[in]     ctx        Resolver context
 * @param[in,out] res        Result object to update
 * @param[in]     candidate  Base domain to query
 * @param[out]    final      Set when the outcome ends the search
 *
 * @returns the outcome class this candidate produced
 */
static enum tlshd_dane_outcome
tlshd_dane_evaluate_candidate(struct ub_ctx *ctx,
			      struct tlshd_dane_result *res,
			      const char *candidate, bool *final)
{
	struct ub_result *r = NULL;
	char *qname;
	int ret;

	*final = false;
	qname = g_strdup_printf("_%u._%s.%s.", res->port,
				tlshd_dane_proto_label(res->ip_proto),
				candidate);
	tlshd_log_debug("DANE: querying TLSA at %s", qname);

	ret = ub_resolve(ctx, qname, TLSHD_DNS_TYPE_TLSA,
			 TLSHD_DNS_CLASS_IN, &r);
	g_free(qname);
	if (ret || !r) {
		ub_resolve_free(r);
		tlshd_dane_set_reason(res, "TLSA lookup failed: %s",
				      ub_strerror(ret));
		*final = true;
		return TLSHD_DANE_ERROR;
	}
	if (r->bogus) {
		tlshd_dane_set_reason(res, "TLSA lookup is bogus: %s",
				      r->why_bogus ? r->why_bogus :
				      "no detail");
		ub_resolve_free(r);
		*final = true;
		return TLSHD_DANE_ERROR;
	}
	if (r->rcode != TLSHD_DNS_RCODE_NOERROR &&
	    r->rcode != TLSHD_DNS_RCODE_NXDOMAIN) {
		tlshd_dane_set_reason(res, "TLSA lookup rcode %d", r->rcode);
		ub_resolve_free(r);
		*final = true;
		return TLSHD_DANE_ERROR;
	}

	if (!r->secure) {
		/*
		 * An unsigned span, records or denial alike. Not final:
		 * the next candidate may still be signed.
		 */
		tlshd_dane_set_reason(res, "no DNSSEC signature at %s",
				      candidate);
		ub_resolve_free(r);
		return TLSHD_DANE_INSECURE;
	}
	if (!r->havedata) {
		tlshd_dane_set_reason(res, "validated denial at %s", candidate);
		ub_resolve_free(r);
		return TLSHD_DANE_SECURE_ABSENT;
	}

	/*
	 * A validated RRset ends the search whether or not this
	 * implementation can use any of its records.
	 */
	*final = true;
	res->tlsa = r;
	tlshd_dane_select_records(res);
	if (!res->nrecords) {
		tlshd_dane_set_reason(res,
				      "validated RRset at %s has no usable DANE-EE record",
				      candidate);
		return TLSHD_DANE_SECURE_UNUSABLE;
	}
	tlshd_dane_set_reason(res, "%u usable DANE-EE record(s) at %s",
			      res->nrecords, candidate);
	return TLSHD_DANE_SECURE_USABLE;
}

/**
 * @brief Run the TLSA lookup algorithm over the candidate base domains
 * @param[in,out] res  Result object to fill in
 */
static void tlshd_dane_query(struct tlshd_dane_result *res)
{
	char *candidates[2] = { NULL, NULL };
	struct ub_ctx *ctx;
	unsigned int i, n;
	char *why = NULL;

	ctx = tlshd_dane_resolver(&why);
	if (!ctx) {
		res->outcome = TLSHD_DANE_ERROR;
		tlshd_dane_set_reason(res, "%s", why);
		g_free(why);
		return;
	}

	n = 0;
	if (!tlshd_dane_expanded_name(ctx, res, &candidates[n])) {
		res->outcome = TLSHD_DANE_ERROR;
		ub_ctx_delete(ctx);
		return;
	}
	if (candidates[n])
		n++;
	candidates[n++] = g_strdup(res->refname);

	for (i = 0; i < n; i++) {
		enum tlshd_dane_outcome outcome;
		bool final;

		outcome = tlshd_dane_evaluate_candidate(ctx, res,
							candidates[i], &final);
		g_free(res->base_domain);
		res->base_domain = g_strdup(candidates[i]);
		res->outcome = outcome;
		if (final)
			break;
	}

	for (i = 0; i < n; i++)
		g_free(candidates[i]);
	ub_ctx_delete(ctx);
}

/**
 * @brief Determine and apply DANE policy before the ClientHello
 * @param[in,out] parms  Handshake parameters
 *
 * Call before setting SNI: the selected TLSA base domain is the SNI
 * value.
 *
 * @retval true   The handshake may proceed
 * @retval false  Policy forbids the handshake; session_status is set
 */
bool tlshd_dane_evaluate(struct tlshd_handshake_parms *parms)
{
	struct tlshd_dane_result *res;
	enum tlshd_dane_mode mode;
	char *why = NULL;

	mode = tlshd_config_get_dane_mode();
	if (mode == TLSHD_DANE_MODE_OFF)
		return true;

	res = g_new0(struct tlshd_dane_result, 1);
	res->mode = mode;
	res->mode_source = "config";
	res->outcome = TLSHD_DANE_NOT_APPLICABLE;
	res->port = parms->peerport;
	res->ip_proto = parms->ip_proto;
	parms->dane = res;

	/* A name synthesized from reverse DNS is not a reference identity. */
	if (!parms->peername_explicit) {
		tlshd_dane_set_reason(res,
				      "peer name was not supplied by the kernel");
		goto out_check;
	}
	if (!tlshd_dane_proto_label(res->ip_proto)) {
		tlshd_dane_set_reason(res, "transport protocol %d is not TCP",
				      res->ip_proto);
		goto out_check;
	}
	if (!res->port) {
		tlshd_dane_set_reason(res, "no peer port");
		goto out_check;
	}

	res->refname = tlshd_dane_normalize_name(parms->peername, res->port,
						 tlshd_dane_proto_label(res->ip_proto),
						 &why);
	if (!res->refname) {
		tlshd_dane_set_reason(res, "%s", why);
		g_free(why);
		goto out_check;
	}

	tlshd_dane_query(res);

out_check:
	switch (res->outcome) {
	case TLSHD_DANE_SECURE_USABLE:
		/* DANE governs; the verify callback matches the peer. */
		return true;
	case TLSHD_DANE_SECURE_UNUSABLE:
	case TLSHD_DANE_SECURE_ABSENT:
	case TLSHD_DANE_INSECURE:
	case TLSHD_DANE_NOT_APPLICABLE:
		if (mode != TLSHD_DANE_MODE_REQUIRE)
			return true;
		break;
	case TLSHD_DANE_ERROR:
		/* A lookup error never permits proceeding, in either mode. */
		break;
	}

	tlshd_log_error("DANE: refusing to handshake with '%s': %s (%s)",
			parms->peername ? parms->peername : "(unknown)",
			res->reason ? res->reason : "no detail",
			tlshd_dane_outcome_name(res->outcome));
	parms->session_status = EACCES;
	return false;
}

/**
 * @brief Report the name to send in the SNI extension
 * @param[in]     parms  Handshake parameters
 *
 * Where DANE authenticates the peer, the selected TLSA base domain
 * (RFC 7671 Section 7). Otherwise the normalized reference name, which
 * is what RFC 9289 PKIX matches the certificate against. The two
 * differ only for a securely CNAME-expanded name whose RRset holds no
 * usable DANE-EE record. RFC 7671 Sections 7 and 10.2 make the base
 * domain a reference identity for usages this round does not
 * implement, so DANE-TA support must revisit this.
 *
 * @returns a name owned by the handshake parameters
 */
const char *tlshd_dane_sni_name(const struct tlshd_handshake_parms *parms)
{
	if (parms->dane) {
		if (parms->dane->outcome == TLSHD_DANE_SECURE_USABLE &&
		    parms->dane->base_domain)
			return parms->dane->base_domain;
		if (parms->dane->refname)
			return parms->dane->refname;
	}
	return parms->peername;
}

/**
 * @brief Match the peer's certificate chain against the TLSA RRset
 * @param[in,out] parms    Handshake parameters
 * @param[in]     session  Session in the midst of a handshake
 *
 * @retval 1   The peer was authenticated by a DANE-EE record
 * @retval 0   DANE does not govern; the caller must complete PKIX
 * @retval -1  Authentication failed
 */
int tlshd_dane_verify(struct tlshd_handshake_parms *parms,
		      gnutls_session_t session)
{
	unsigned int vflags = DANE_VFLAG_ONLY_CHECK_EE_USAGE |
			      DANE_VFLAG_FAIL_IF_NOT_CHECKED;
	struct tlshd_dane_result *res = parms->dane;
	const gnutls_datum_t *chain;
	unsigned int i, chain_len;
	dane_state_t state;
	int ret;

	if (!res || res->outcome != TLSHD_DANE_SECURE_USABLE)
		return 0;

	chain = gnutls_certificate_get_peers(session, &chain_len);
	if (!chain || !chain_len) {
		tlshd_dane_set_reason(res, "peer presented no certificate");
		return -1;
	}

	/*
	 * libunbound already validated the RRset. libgnutls-dane must
	 * not resolve or apply a trust anchor of its own.
	 */
	ret = dane_state_init(&state,
			      DANE_F_IGNORE_DNSSEC | DANE_F_IGNORE_LOCAL_RESOLVER);
	if (ret != DANE_E_SUCCESS) {
		tlshd_dane_set_reason(res, "dane_state_init: %s",
				      dane_strerror(ret));
		return -1;
	}

	/*
	 * One record per call, so the audit event can name the record
	 * that matched and so the digest-agility filtering above, not
	 * libgnutls-dane's, decides which records are eligible.
	 */
	for (i = 0; i < res->nrecords; i++) {
		struct tlshd_dane_record *rec = &res->records[i];
		char *rdata[2] = { res->tlsa->data[rec->index], NULL };
		int rdata_len[2] = { res->tlsa->len[rec->index], 0 };
		unsigned int verify = 0;
		dane_query_t query;

		ret = dane_raw_tlsa(state, &query, rdata, rdata_len, 1, 0);
		if (ret != DANE_E_SUCCESS) {
			tlshd_log_debug("DANE: dane_raw_tlsa: %s",
					dane_strerror(ret));
			continue;
		}

		ret = dane_verify_crt_raw(state, chain, chain_len,
					  GNUTLS_CRT_X509, query, 0, vflags,
					  &verify);
		dane_query_deinit(query);

		/*
		 * The return value says only whether the check ran; the
		 * verdict is in the bitmask.
		 */
		if (ret != DANE_E_SUCCESS || verify)
			continue;

		res->matched = true;
		res->match = *rec;
		res->dane_auth = true;
		tlshd_dane_set_reason(res,
				      "matched TLSA %u %u %u at %s",
				      rec->usage, rec->selector, rec->match,
				      res->base_domain);
		dane_state_deinit(state);
		return 1;
	}

	dane_state_deinit(state);
	tlshd_dane_set_reason(res,
			      "no TLSA record at %s matches the peer certificate",
			      res->base_domain);
	return -1;
}

/**
 * @brief Record the result of PKIX authentication
 * @param[in,out] parms          Handshake parameters
 * @param[in]     authenticated  Whether PKIX validation succeeded
 */
void tlshd_dane_record_pkix(struct tlshd_handshake_parms *parms,
			    bool authenticated)
{
	if (parms->dane)
		parms->dane->pkix_auth = authenticated;
}

/**
 * @brief Record that this handshake authenticates no one, by design
 * @param[in,out] parms  Handshake parameters
 */
void tlshd_dane_record_unauth(struct tlshd_handshake_parms *parms)
{
	if (parms->dane)
		parms->dane->unauth = true;
}

/**
 * @brief Record that this handshake resumed an earlier session
 * @param[in,out] parms  Handshake parameters
 */
void tlshd_dane_record_resumed(struct tlshd_handshake_parms *parms)
{
	if (parms->dane)
		parms->dane->resumed = true;
}

/*
 * The audit event is one line of key=value fields, and the
 * peername arrives from the kernel unvalidated. Replace any
 * character that could forge a field boundary.
 */
static void tlshd_dane_audit_name(const char *name, char *buf, size_t buflen)
{
	size_t i;

	for (i = 0; name[i] && i < buflen - 1; i++) {
		unsigned char c = (unsigned char)name[i];

		if (g_ascii_isalnum(c) || c == '.' || c == '-' ||
		    c == '_' || c == ':')
			buf[i] = c;
		else
			buf[i] = '?';
	}
	buf[i] = '\0';
}

/**
 * @brief Emit the DANE authentication audit event
 * @param[in,out] parms  Handshake parameters
 *
 * RFC 9289 Section 5.3 requires an audit log of security mode
 * selection. This is tlshd's half of that record and reports only
 * what tlshd observes; probe results and cleartext fallback are the
 * kernel's decisions and belong to its event. Emitted once per
 * handshake, regardless of tlshd_debug.
 */
void tlshd_dane_audit(struct tlshd_handshake_parms *parms)
{
	struct tlshd_dane_result *res = parms->dane;
	char peername[TLSHD_DNS_MAX_NAME + 1] = "(none)";
	char matched_rr[64] = "none";
	const char *auth = "none";
	int priority = LOG_NOTICE;

	if (!res || res->audited)
		return;
	res->audited = true;

	if (res->dane_auth)
		auth = "dane-ee";
	else if (res->pkix_auth)
		auth = "pkix";
	else if (res->unauth)
		auth = "unauth";
	else if (res->resumed)
		auth = "resumed";
	else
		priority = LOG_ERR;

	if (parms->peername)
		tlshd_dane_audit_name(parms->peername, peername,
				      sizeof(peername));

	if (res->matched)
		snprintf(matched_rr, sizeof(matched_rr), "%u/%u/%u",
			 res->match.usage, res->match.selector,
			 res->match.match);

	tlshd_log_audit(priority,
			"DANE audit: peername=%s provenance=%s peeraddr=%s "
			"port=%u proto=%d mode=%s policy_source=%s "
			"outcome=%s base_domain=%s usable_records=%u "
			"match=%s auth=%s reason=%s",
			peername,
			parms->peername_explicit ? "kernel" : "reverse-dns",
			parms->peeraddr ? parms->peeraddr : "(none)",
			parms->peerport, parms->ip_proto,
			tlshd_dane_mode_name(res->mode), res->mode_source,
			tlshd_dane_outcome_name(res->outcome),
			res->base_domain ? res->base_domain : "(none)",
			res->nrecords, matched_rr, auth,
			res->reason ? res->reason : "(none)");
}

/**
 * @brief Release a retained DANE evaluation
 * @param[in,out] parms  Handshake parameters
 */
void tlshd_dane_release(struct tlshd_handshake_parms *parms)
{
	struct tlshd_dane_result *res = parms->dane;

	if (!res)
		return;
	parms->dane = NULL;

	g_free(res->records);
	ub_resolve_free(res->tlsa);
	g_free(res->base_domain);
	g_free(res->refname);
	g_free(res->reason);
	g_free(res);
}
