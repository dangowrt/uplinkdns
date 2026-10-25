/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

static int status_herrno(int status)
{
	switch (status) {
	case ARES_ENOTFOUND:
		return HOST_NOT_FOUND;
	case ARES_ENODATA:
		return NO_DATA;
	case ARES_ETIMEOUT:
	case ARES_ECONNREFUSED:
	case ARES_ESERVFAIL:
		return TRY_AGAIN;
	default:
		return NO_RECOVERY;
	}
}

static int status_errno(int status)
{
	switch (status) {
	case ARES_ETIMEOUT:
		return ETIMEDOUT;
	case ARES_ECONNREFUSED:
		return ECONNREFUSED;
	case ARES_ENOMEM:
		return ENOMEM;
	default:
		return EIO;
	}
}

static int answer_herrno(const struct raw_answer *ans)
{
	switch (ans->rcode) {
	case ARES_RCODE_NOERROR:
		return ans->ancount ? 0 : NO_DATA;
	case ARES_RCODE_NXDOMAIN:
		return HOST_NOT_FOUND;
	case ARES_RCODE_SERVFAIL:
		return TRY_AGAIN;
	default:
		return NO_RECOVERY;
	}
}

static int uplink_query(struct uplink *up, const struct raw_request *raw,
			unsigned char *answer, int anslen)
{
	struct raw_answer ans;
	size_t copied;
	int status;
	int herr;
	int len;

	status = resolver_raw(up, raw, &ans);
	if (!ans.buf) {
		h_errno = status_herrno(status);
		errno = status_errno(status);
		return -1;
	}

	copied = anslen > 0 && ans.len > (size_t)anslen ? (size_t)anslen :
							   ans.len;
	if (anslen > 0)
		memcpy(answer, ans.buf, copied);

	len = ans.len > INT_MAX ? INT_MAX : (int)ans.len;
	herr = raw->kind == RAW_SEND ? 0 : answer_herrno(&ans);
	ares_free_string(ans.buf);
	if (herr) {
		h_errno = herr;
		return -1;
	}

	return len;
}

static int name_query(struct uplink *up, enum raw_kind kind, const char *name,
		      int dnsclass, int type, unsigned char *answer,
		      int anslen)
{
	struct raw_request raw;

	memset(&raw, 0, sizeof(raw));
	raw.kind = kind;
	raw.name = name;
	raw.dnsclass = dnsclass;
	raw.type = type;
	return uplink_query(up, &raw, answer, anslen);
}

static int domain_query(struct uplink *up, const char *name,
			const char *domain, int dnsclass, int type,
			unsigned char *answer, int anslen)
{
	size_t len;
	char *full;
	int ret;

	if (!domain || !*domain)
		return name_query(up, RAW_QUERY, name, dnsclass, type, answer,
				  anslen);

	len = strlen(name) + strlen(domain) + 2;
	full = malloc(len);
	if (!full) {
		h_errno = NO_RECOVERY;
		errno = ENOMEM;
		return -1;
	}

	snprintf(full, len, "%s.%s", name, domain);
	ret = name_query(up, RAW_QUERY, full, dnsclass, type, answer, anslen);
	free(full);
	return ret;
}

static int message_send(struct uplink *up, const unsigned char *msg,
			int msglen, unsigned char *answer, int anslen)
{
	struct raw_request raw;

	if (msglen < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&raw, 0, sizeof(raw));
	raw.kind = RAW_SEND;
	raw.msg = msg;
	raw.msg_len = (size_t)msglen;
	return uplink_query(up, &raw, answer, anslen);
}

static int real_missing(void)
{
	h_errno = NO_RECOVERY;
	errno = ENOSYS;
	return -1;
}

UPLINKDNS_EXPORT int res_query(const char *name, int dnsclass, int type,
			       unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return name_query(up, RAW_QUERY, name, dnsclass, type, answer,
				  anslen);

	if (!real.res_query)
		return real_missing();

	return real.res_query(name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int res_search(const char *name, int dnsclass, int type,
				unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return name_query(up, RAW_SEARCH, name, dnsclass, type, answer,
				  anslen);

	if (!real.res_search)
		return real_missing();

	return real.res_search(name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int res_querydomain(const char *name, const char *domain,
				     int dnsclass, int type,
				     unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return domain_query(up, name, domain, dnsclass, type, answer,
				    anslen);

	if (!real.res_querydomain)
		return real_missing();

	return real.res_querydomain(name, domain, dnsclass, type, answer,
				    anslen);
}

UPLINKDNS_EXPORT int res_send(const unsigned char *msg, int msglen,
			      unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return message_send(up, msg, msglen, answer, anslen);

	if (!real.res_send)
		return real_missing();

	return real.res_send(msg, msglen, answer, anslen);
}

#ifdef __GLIBC__
UPLINKDNS_EXPORT int res_nquery(void *statp, const char *name, int dnsclass,
				int type, unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return name_query(up, RAW_QUERY, name, dnsclass, type, answer,
				  anslen);

	if (!real.res_nquery)
		return real_missing();

	return real.res_nquery(statp, name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int res_nsearch(void *statp, const char *name, int dnsclass,
				 int type, unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return name_query(up, RAW_SEARCH, name, dnsclass, type, answer,
				  anslen);

	if (!real.res_nsearch)
		return real_missing();

	return real.res_nsearch(statp, name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int res_nquerydomain(void *statp, const char *name,
				      const char *domain, int dnsclass,
				      int type, unsigned char *answer,
				      int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return domain_query(up, name, domain, dnsclass, type, answer,
				    anslen);

	if (!real.res_nquerydomain)
		return real_missing();

	return real.res_nquerydomain(statp, name, domain, dnsclass, type,
				     answer, anslen);
}

UPLINKDNS_EXPORT int res_nsend(void *statp, const unsigned char *msg,
			       int msglen, unsigned char *answer, int anslen)
{
	struct uplink *up;

	real_init();
	up = context_uplink();
	if (up)
		return message_send(up, msg, msglen, answer, anslen);

	if (!real.res_nsend)
		return real_missing();

	return real.res_nsend(statp, msg, msglen, answer, anslen);
}

/* binaries linked against glibc before 2.34 reference these names */
UPLINKDNS_EXPORT int __res_query(const char *name, int dnsclass, int type,
				 unsigned char *answer, int anslen)
{
	return res_query(name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int __res_search(const char *name, int dnsclass, int type,
				  unsigned char *answer, int anslen)
{
	return res_search(name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int __res_querydomain(const char *name, const char *domain,
				       int dnsclass, int type,
				       unsigned char *answer, int anslen)
{
	return res_querydomain(name, domain, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int __res_send(const unsigned char *msg, int msglen,
				unsigned char *answer, int anslen)
{
	return res_send(msg, msglen, answer, anslen);
}

UPLINKDNS_EXPORT int __res_nquery(void *statp, const char *name, int dnsclass,
				  int type, unsigned char *answer, int anslen)
{
	return res_nquery(statp, name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int __res_nsearch(void *statp, const char *name,
				   int dnsclass, int type,
				   unsigned char *answer, int anslen)
{
	return res_nsearch(statp, name, dnsclass, type, answer, anslen);
}

UPLINKDNS_EXPORT int __res_nquerydomain(void *statp, const char *name,
					const char *domain, int dnsclass,
					int type, unsigned char *answer,
					int anslen)
{
	return res_nquerydomain(statp, name, domain, dnsclass, type, answer,
				anslen);
}

UPLINKDNS_EXPORT int __res_nsend(void *statp, const unsigned char *msg,
				 int msglen, unsigned char *answer, int anslen)
{
	return res_nsend(statp, msg, msglen, answer, anslen);
}
#endif
