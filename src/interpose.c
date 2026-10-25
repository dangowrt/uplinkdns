/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "internal.h"
#include "uplinkdns.h"

struct result_node {
	struct sockaddr_storage ss;
	struct addrinfo ai;
};

static pthread_mutex_t result_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int context_current = UPLINKDNS_CTX_DEFER;
static void *result_tree;

int context_get(void)
{
	return context_current;
}

void context_put(int ctx)
{
	context_current = ctx;
}

struct uplink *context_uplink(void)
{
	return context_current >= 0 ? uplink_by_id(context_current) : NULL;
}

static int ptr_cmp(const void *a, const void *b)
{
	uintptr_t pa = (uintptr_t)a;
	uintptr_t pb = (uintptr_t)b;

	if (pa == pb)
		return 0;

	return pa < pb ? -1 : 1;
}

static void results_free(struct addrinfo *ai)
{
	struct result_node *node;
	struct addrinfo *next;

	for (; ai; ai = next) {
		next = ai->ai_next;
		node = (struct result_node *)((char *)ai -
					      offsetof(struct result_node, ai));
		free(ai->ai_canonname);
		free(node);
	}
}

static int results_register(struct addrinfo *head)
{
	void *found;

	pthread_mutex_lock(&result_lock);
	found = tsearch(head, &result_tree, ptr_cmp);
	pthread_mutex_unlock(&result_lock);

	return found ? 0 : EAI_MEMORY;
}

static bool results_unregister(struct addrinfo *head)
{
	void *found;

	pthread_mutex_lock(&result_lock);
	found = tfind(head, &result_tree, ptr_cmp);
	if (found)
		tdelete(head, &result_tree, ptr_cmp);
	pthread_mutex_unlock(&result_lock);

	return found;
}

void addrinfo_release(struct addrinfo *res)
{
	if (!res)
		return;

	if (results_unregister(res))
		results_free(res);
	else
		real.freeaddrinfo(res);
}

static int addrinfo_append(struct addrinfo ***tail,
			   const struct addrinfo *part,
			   const struct sockaddr_storage *addr)
{
	const struct sockaddr_in6 *addr6;
	const struct addrinfo *p;
	struct result_node *node;
	struct sockaddr_in6 *ss6;

	addr6 = (const struct sockaddr_in6 *)addr;
	for (p = part; p; p = p->ai_next) {
		if (p->ai_addrlen > sizeof(node->ss))
			continue;

		node = calloc(1, sizeof(*node));
		if (!node)
			return EAI_MEMORY;

		node->ai.ai_flags = p->ai_flags;
		node->ai.ai_family = p->ai_family;
		node->ai.ai_socktype = p->ai_socktype;
		node->ai.ai_protocol = p->ai_protocol;
		node->ai.ai_addrlen = p->ai_addrlen;
		memcpy(&node->ss, p->ai_addr, p->ai_addrlen);
		if (p->ai_family == AF_INET6 && addr->ss_family == AF_INET6) {
			ss6 = (struct sockaddr_in6 *)&node->ss;
			ss6->sin6_scope_id = addr6->sin6_scope_id;
		}

		node->ai.ai_addr = (struct sockaddr *)&node->ss;
		**tail = &node->ai;
		*tail = &node->ai.ai_next;
	}

	return 0;
}

static int addrinfo_numeric_get(const struct sockaddr_storage *addr,
				const char *service,
				const struct addrinfo *hints,
				struct addrinfo **part)
{
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
	const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
	char host[INET6_ADDRSTRLEN];
	const void *inaddr;
	struct addrinfo h;

	inaddr = addr->ss_family == AF_INET ? (const void *)&sin->sin_addr :
					      (const void *)&sin6->sin6_addr;
	if (!inet_ntop(addr->ss_family, inaddr, host, sizeof(host)))
		return EAI_FAMILY;

	memset(&h, 0, sizeof(h));
	h.ai_family = addr->ss_family;
	h.ai_flags = AI_NUMERICHOST;
	if (hints) {
		h.ai_socktype = hints->ai_socktype;
		h.ai_protocol = hints->ai_protocol;
		h.ai_flags |= hints->ai_flags & AI_NUMERICSERV;
	}

	return real.getaddrinfo(host, service, &h, part);
}

static int addrinfo_build(const struct addr_list *list, const char *canon,
			  const char *service, const struct addrinfo *hints,
			  struct addrinfo **res)
{
	struct addrinfo *head = NULL;
	struct addrinfo **tail;
	struct addrinfo *part;
	int ret = 0;
	size_t i;

	tail = &head;
	for (i = 0; !ret && i < list->count; i++) {
		ret = addrinfo_numeric_get(&list->addrs[i], service, hints,
					   &part);
		if (ret)
			break;

		ret = addrinfo_append(&tail, part, &list->addrs[i]);
		real.freeaddrinfo(part);
	}

	if (!ret && !head)
		ret = EAI_NONAME;

	if (!ret && hints && hints->ai_flags & AI_CANONNAME) {
		head->ai_canonname = strdup(canon);
		if (!head->ai_canonname)
			ret = EAI_MEMORY;
	}

	if (!ret)
		ret = results_register(head);

	if (ret) {
		results_free(head);
		return ret;
	}

	*res = head;
	return 0;
}

static void sockaddr4_set(struct sockaddr_storage *ss,
			  const struct in_addr *addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	memset(ss, 0, sizeof(*ss));
	sin->sin_family = AF_INET;
	sin->sin_addr = *addr;
}

static void sockaddr6_set(struct sockaddr_storage *ss,
			  const struct in6_addr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = *addr;
}

static void sockaddr_v4map(struct sockaddr_storage *ss)
{
	struct in6_addr mapped;
	struct in_addr addr4;

	addr4 = ((struct sockaddr_in *)ss)->sin_addr;
	memset(&mapped, 0, sizeof(mapped));
	mapped.s6_addr[10] = 0xff;
	mapped.s6_addr[11] = 0xff;
	memcpy(&mapped.s6_addr[12], &addr4, sizeof(addr4));
	sockaddr6_set(ss, &mapped);
}

static bool addr_list_has(const struct addr_list *list, int family)
{
	size_t i;

	for (i = 0; i < list->count; i++) {
		if (list->addrs[i].ss_family == family)
			return true;
	}

	return false;
}

static void addr_list_filter(struct addr_list *list, bool keep4, bool keep6,
			     bool map4)
{
	struct sockaddr_storage *ss;
	size_t n = 0;
	size_t i;

	for (i = 0; i < list->count; i++) {
		ss = &list->addrs[i];
		if (ss->ss_family == AF_INET && map4)
			sockaddr_v4map(ss);
		else if (ss->ss_family == AF_INET && !keep4)
			continue;
		else if (ss->ss_family == AF_INET6 && !keep6)
			continue;

		list->addrs[n++] = *ss;
	}

	list->count = n;
}

static bool host_family_configured(int family)
{
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_in *sin;
	struct ifaddrs *ifas;
	struct ifaddrs *ifa;
	bool found = false;

	if (getifaddrs(&ifas))
		return true;

	for (ifa = ifas; ifa && !found; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != family)
			continue;

		sin = (const struct sockaddr_in *)ifa->ifa_addr;
		sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
		if (family == AF_INET)
			found = ntohl(sin->sin_addr.s_addr) >> 24 != IN_LOOPBACKNET;
		else
			found = !IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) &&
				!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr);
	}

	freeifaddrs(ifas);
	return found;
}

static bool family_valid(int family)
{
	return family == AF_UNSPEC || family == AF_INET || family == AF_INET6;
}

static int uplink_addrinfo(struct uplink *up, const char *node,
			   const char *service, const struct addrinfo *hints,
			   struct addrinfo **res)
{
	struct addr_list list;
	char *canon = NULL;
	bool map4 = false;
	bool keep4;
	bool keep6;
	int family;
	int flags;
	int query;
	int ret;

	family = hints ? hints->ai_family : AF_UNSPEC;
	flags = hints ? hints->ai_flags : 0;
	if (!family_valid(family))
		return EAI_FAMILY;

	query = family == AF_INET6 && flags & AI_V4MAPPED ? AF_UNSPEC : family;
	ret = resolver_lookup(up, node, query, &list, &canon);
	if (ret)
		return ret;

	keep4 = family != AF_INET6;
	keep6 = family != AF_INET;
	if (family == AF_INET6 && flags & AI_V4MAPPED)
		map4 = flags & AI_ALL || !addr_list_has(&list, AF_INET6);

	if (flags & AI_ADDRCONFIG) {
		keep4 = keep4 && uplink_family_usable(up, AF_INET);
		keep6 = keep6 && uplink_family_usable(up, AF_INET6);
		map4 = map4 && uplink_family_usable(up, AF_INET);
	}

	addr_list_filter(&list, keep4, keep6, map4);
	ret = list.count ? addrinfo_build(&list, canon, service, hints, res) :
			   EAI_NONAME;

	free(canon);
	addr_list_free(&list);
	return ret;
}

static int synth_addrinfo(const char *node, const char *service,
			  const struct addrinfo *hints,
			  struct addrinfo **res)
{
	struct sockaddr_storage addrs[SYNTH_SLOTS + 1];
	struct in6_addr v6_aaaa;
	struct addr_list list;
	struct in6_addr v6_a;
	struct in_addr v4;
	bool want4;
	bool want6;
	int family;
	bool map4;
	int flags;
	int ret;

	family = hints ? hints->ai_family : AF_UNSPEC;
	flags = hints ? hints->ai_flags : 0;
	if (!family_valid(family))
		return EAI_FAMILY;

	want6 = family != AF_INET;
	want4 = family != AF_INET6;
	map4 = family == AF_INET6 && flags & AI_V4MAPPED;
	if (flags & AI_ADDRCONFIG) {
		want6 = want6 && host_family_configured(AF_INET6);
		want4 = want4 && host_family_configured(AF_INET);
		map4 = map4 && host_family_configured(AF_INET);
	}

	if (!want4 && !want6 && !map4)
		return EAI_NONAME;

	ret = synth_name_assign(node, &v4, &v6_aaaa, &v6_a);
	if (ret)
		return ret;

	list.addrs = addrs;
	list.count = 0;
	if (want6)
		sockaddr6_set(&addrs[list.count++], &v6_aaaa);
	if (map4)
		sockaddr6_set(&addrs[list.count++], &v6_a);
	if (want4)
		sockaddr4_set(&addrs[list.count++], &v4);

	debug_log("defer %s", node);
	return addrinfo_build(&list, node, service, hints, res);
}

static bool name_is_localhost(const char *node)
{
	static const char suffix[] = ".localhost";
	static const char name[] = "localhost";
	size_t slen = sizeof(suffix) - 1;
	size_t len;

	len = strlen(node);
	if (len && node[len - 1] == '.')
		len--;

	if (len == sizeof(name) - 1 && !strncasecmp(node, name, len))
		return true;

	return len > slen && !strncasecmp(node + len - slen, suffix, slen);
}

bool addrinfo_bypass(int ctx, const char *node, const struct addrinfo *hints)
{
	int flags = hints ? hints->ai_flags : 0;

	if (!node || ctx == UPLINKDNS_CTX_SYSTEM)
		return true;

	if (flags & (AI_NUMERICHOST | AI_PASSIVE) || name_is_localhost(node))
		return true;

	return ctx == UPLINKDNS_CTX_DEFER && !uplink_any_registered();
}

int addrinfo_resolve(int ctx, const char *node, const char *service,
		     const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo numeric;
	struct uplink *up;
	int ret;

	if (addrinfo_bypass(ctx, node, hints))
		return real.getaddrinfo(node, service, hints, res);

	memset(&numeric, 0, sizeof(numeric));
	if (hints) {
		numeric.ai_flags = hints->ai_flags;
		numeric.ai_family = hints->ai_family;
		numeric.ai_socktype = hints->ai_socktype;
		numeric.ai_protocol = hints->ai_protocol;
	}
	numeric.ai_flags |= AI_NUMERICHOST;

	ret = real.getaddrinfo(node, service, &numeric, res);
	if (ret != EAI_NONAME)
		return ret;

	if (ctx == UPLINKDNS_CTX_DEFER)
		return synth_addrinfo(node, service, hints, res);

	up = uplink_by_id(ctx);
	if (!up)
		return EAI_FAIL;

	return uplink_addrinfo(up, node, service, hints, res);
}

static int eai_errno(int eai)
{
	switch (eai) {
	case EAI_AGAIN:
		return ETIMEDOUT;
	case EAI_MEMORY:
		return ENOMEM;
	case EAI_SYSTEM:
		return errno;
	default:
		return EHOSTUNREACH;
	}
}

static int target_v4mapped(int fd, const struct sockaddr_in6 *want6,
			   struct sockaddr_storage *out, socklen_t *outlen)
{
	struct sockaddr_in6 *out6;
	socklen_t len;
	int v6only;

	v6only = 0;
	len = sizeof(v6only);
	if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &len) ||
	    v6only) {
		errno = ENETUNREACH;
		return -1;
	}

	sockaddr_v4map(out);
	out6 = (struct sockaddr_in6 *)out;
	out6->sin6_port = want6->sin6_port;
	*outlen = sizeof(*out6);

	return 1;
}

static int target_build(int fd, const struct sockaddr *sa,
			const struct sockaddr_storage *chosen,
			struct sockaddr_storage *out, socklen_t *outlen)
{
	const struct sockaddr_in6 *want6 = (const struct sockaddr_in6 *)sa;
	const struct sockaddr_in *want4 = (const struct sockaddr_in *)sa;
	struct sockaddr_in6 *out6 = (struct sockaddr_in6 *)out;
	struct sockaddr_in *out4 = (struct sockaddr_in *)out;

	*out = *chosen;
	if (sa->sa_family == AF_INET) {
		if (chosen->ss_family != AF_INET) {
			errno = ENETUNREACH;
			return -1;
		}

		out4->sin_port = want4->sin_port;
		*outlen = sizeof(*out4);
		return 1;
	}

	if (chosen->ss_family == AF_INET)
		return target_v4mapped(fd, want6, out, outlen);

	out6->sin6_port = want6->sin6_port;
	out6->sin6_flowinfo = want6->sin6_flowinfo;
	*outlen = sizeof(*out6);
	return 1;
}

static struct uplink *target_uplink(int fd)
{
	struct uplink *up;

	up = uplink_of_socket(fd);
	if (!up)
		up = context_uplink();

	return up;
}

static void target_log(bool local, const char *name, const struct uplink *up,
		       const struct sockaddr_storage *target)
{
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)target;
	const struct sockaddr_in *sin = (const struct sockaddr_in *)target;
	char addr[INET6_ADDRSTRLEN] = "?";
	const void *inaddr;

	inaddr = target->ss_family == AF_INET ? (const void *)&sin->sin_addr :
						(const void *)&sin6->sin6_addr;
	inet_ntop(target->ss_family, inaddr, addr, sizeof(addr));
	debug_log("%s %s via %s: %s", local ? "bind" : "connect", name,
		  up ? up->key : "system", addr);
}

static int target_resolve(int fd, const struct sockaddr *sa, bool local,
			  struct sockaddr_storage *out, socklen_t *outlen)
{
	unsigned int rotation = 0;
	struct uplink *up = NULL;
	struct addr_list list;
	enum synth_slot slot;
	char *name;
	int family;
	int ret;

	name = synth_name_get(sa, &slot, local ? NULL : &rotation);
	if (!name) {
		if (sa->sa_family == AF_INET && errno == ENOENT)
			return 0;
		if (errno != ENOMEM)
			errno = EHOSTUNREACH;
		return -1;
	}

	if (!local)
		up = target_uplink(fd);

	family = slot == SYNTH_SLOT_AAAA ? AF_INET6 : AF_INET;
	if (up && !uplink_family_usable(up, family)) {
		debug_log("connect %s via %s: no family %d", name, up->key,
			  family);
		free(name);
		errno = ENETUNREACH;
		return -1;
	}

	ret = up ? resolver_lookup(up, name, family, &list, NULL) :
		   system_lookup(name, family, &list, NULL);
	if (ret) {
		debug_log("%s %s: %s", local ? "bind" : "connect", name,
			  gai_strerror(ret));
		errno = eai_errno(ret);
		free(name);
		return -1;
	}

	ret = target_build(fd, sa, &list.addrs[rotation % list.count], out,
			   outlen);
	if (ret > 0 && debug_enabled)
		target_log(local, name, up, out);

	free(name);
	addr_list_free(&list);
	return ret;
}

UPLINKDNS_EXPORT int getaddrinfo(const char *node, const char *service,
				 const struct addrinfo *hints,
				 struct addrinfo **res)
{
	real_init();
	return addrinfo_resolve(context_current, node, service, hints, res);
}

UPLINKDNS_EXPORT void freeaddrinfo(struct addrinfo *res)
{
	real_init();
	addrinfo_release(res);
}

static int nameinfo_fill(const struct sockaddr *sa, socklen_t salen,
			 const char *name, char *host, socklen_t hostlen,
			 char *serv, socklen_t servlen, int flags)
{
	int ret = 0;
	size_t len;

	if (serv && servlen)
		ret = real.getnameinfo(sa, salen, NULL, 0, serv, servlen,
				       flags);
	if (ret)
		return ret;

	len = strlen(name);
	if (len >= hostlen)
		return EAI_OVERFLOW;

	memcpy(host, name, len + 1);
	return 0;
}

UPLINKDNS_EXPORT int getnameinfo(const struct sockaddr *sa, socklen_t salen,
				 char *host, socklen_t hostlen, char *serv,
				 socklen_t servlen, int flags)
{
	enum synth_slot slot;
	struct uplink *up;
	char *name = NULL;
	int ret;

	real_init();
	if (!host || !hostlen || flags & NI_NUMERICHOST)
		return real.getnameinfo(sa, salen, host, hostlen, serv,
					servlen, flags);

	if (synth_is_candidate(sa, salen))
		name = synth_name_get(sa, &slot, NULL);

	up = name ? NULL : context_uplink();
	if (!name && !up)
		return real.getnameinfo(sa, salen, host, hostlen, serv,
					servlen, flags);

	ret = name ? 0 : resolver_reverse(up, sa, salen, flags & NI_NOFQDN,
					  &name);
	if (ret && !(flags & NI_NAMEREQD))
		return real.getnameinfo(sa, salen, host, hostlen, serv,
					servlen, flags | NI_NUMERICHOST);
	if (ret)
		return ret;

	ret = nameinfo_fill(sa, salen, name, host, hostlen, serv, servlen,
			    flags);
	free(name);
	return ret;
}

UPLINKDNS_EXPORT int connect(int fd, const struct sockaddr *sa,
			     socklen_t salen)
{
	struct sockaddr_storage target;
	socklen_t len;
	int ret;

	real_init();
	if (!synth_is_candidate(sa, salen))
		return real.connect(fd, sa, salen);

	ret = target_resolve(fd, sa, false, &target, &len);
	if (ret < 0)
		return -1;
	if (!ret)
		return real.connect(fd, sa, salen);

	return real.connect(fd, (struct sockaddr *)&target, len);
}

UPLINKDNS_EXPORT int bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	struct sockaddr_storage target;
	socklen_t len;
	int ret;

	real_init();
	if (!synth_is_candidate(sa, salen))
		return real.bind(fd, sa, salen);

	ret = target_resolve(fd, sa, true, &target, &len);
	if (ret < 0)
		return -1;
	if (!ret)
		return real.bind(fd, sa, salen);

	return real.bind(fd, (struct sockaddr *)&target, len);
}

UPLINKDNS_EXPORT ssize_t sendto(int fd, const void *buf, size_t size,
				int flags, const struct sockaddr *sa,
				socklen_t salen)
{
	struct sockaddr_storage target;
	socklen_t len;
	int ret;

	real_init();
	if (!synth_is_candidate(sa, salen))
		return real.sendto(fd, buf, size, flags, sa, salen);

	ret = target_resolve(fd, sa, false, &target, &len);
	if (ret < 0)
		return -1;
	if (!ret)
		return real.sendto(fd, buf, size, flags, sa, salen);

	return real.sendto(fd, buf, size, flags, (struct sockaddr *)&target,
			   len);
}

UPLINKDNS_EXPORT ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	struct sockaddr_storage target;
	struct msghdr copy;
	socklen_t len;
	int ret;

	real_init();
	if (!msg || !synth_is_candidate(msg->msg_name, msg->msg_namelen))
		return real.sendmsg(fd, msg, flags);

	ret = target_resolve(fd, msg->msg_name, false, &target, &len);
	if (ret < 0)
		return -1;
	if (!ret)
		return real.sendmsg(fd, msg, flags);

	copy = *msg;
	copy.msg_name = &target;
	copy.msg_namelen = len;
	return real.sendmsg(fd, &copy, flags);
}

static unsigned int mmsg_resolve(int fd, const struct mmsghdr *msgs,
				 unsigned int vlen, struct mmsghdr *copy,
				 struct sockaddr_storage *targets)
{
	const struct msghdr *hdr;
	socklen_t len;
	unsigned int i;
	int ret;

	for (i = 0; i < vlen; i++) {
		copy[i] = msgs[i];
		hdr = &msgs[i].msg_hdr;
		if (!synth_is_candidate(hdr->msg_name, hdr->msg_namelen))
			continue;

		ret = target_resolve(fd, hdr->msg_name, false, &targets[i],
				     &len);
		if (ret < 0)
			break;
		if (!ret)
			continue;

		copy[i].msg_hdr.msg_name = &targets[i];
		copy[i].msg_hdr.msg_namelen = len;
	}

	return i;
}

static bool mmsg_synthetic(const struct mmsghdr *msgs, unsigned int vlen)
{
	unsigned int i;

	for (i = 0; i < vlen; i++) {
		if (synth_is_candidate(msgs[i].msg_hdr.msg_name,
				       msgs[i].msg_hdr.msg_namelen))
			return true;
	}

	return false;
}

UPLINKDNS_EXPORT int sendmmsg(int fd, struct mmsghdr *msgs, unsigned int vlen,
			      SENDMMSG_FLAGS flags)
{
	struct sockaddr_storage *targets;
	struct mmsghdr *copy;
	unsigned int count;
	unsigned int i;
	int ret;

	real_init();
	if (!msgs || !mmsg_synthetic(msgs, vlen))
		return real.sendmmsg(fd, msgs, vlen, flags);

	copy = calloc(vlen, sizeof(*copy));
	targets = calloc(vlen, sizeof(*targets));
	if (!copy || !targets) {
		free(targets);
		free(copy);
		errno = ENOMEM;
		return -1;
	}

	count = mmsg_resolve(fd, msgs, vlen, copy, targets);
	ret = count ? real.sendmmsg(fd, copy, count, flags) : -1;
	for (i = 0; ret > 0 && i < (unsigned int)ret; i++)
		msgs[i].msg_len = copy[i].msg_len;

	free(targets);
	free(copy);
	return ret;
}

UPLINKDNS_EXPORT int uplinkdns_uplink_add(const char *spec)
{
	real_init();
	return uplink_parse_add(spec, true);
}

UPLINKDNS_EXPORT int uplinkdns_context_set(int ctx)
{
	int prev = context_current;

	real_init();
	if (ctx != UPLINKDNS_CTX_DEFER && ctx != UPLINKDNS_CTX_SYSTEM &&
	    !uplink_by_id(ctx))
		return -EINVAL;

	context_current = ctx;
	return prev;
}

UPLINKDNS_EXPORT int uplinkdns_context_get(void)
{
	return context_current;
}

UPLINKDNS_EXPORT int uplinkdns_getaddrinfo(int ctx, const char *node,
					   const char *service,
					   const struct addrinfo *hints,
					   struct addrinfo **res)
{
	real_init();
	if (ctx >= 0 && !uplink_by_id(ctx))
		return EAI_FAIL;

	return addrinfo_resolve(ctx, node, service, hints, res);
}

UPLINKDNS_EXPORT void uplinkdns_freeaddrinfo(struct addrinfo *res)
{
	real_init();
	addrinfo_release(res);
}

UPLINKDNS_EXPORT int uplinkdns_name_get(const struct sockaddr *sa,
					socklen_t salen, char *name,
					size_t len)
{
	enum synth_slot slot;
	char *found;
	int ret = 0;
	size_t n;

	real_init();
	if (!synth_is_candidate(sa, salen))
		return -ENOENT;

	found = synth_name_get(sa, &slot, NULL);
	if (!found)
		return -errno;

	n = strlen(found);
	if (n >= len)
		ret = -ENAMETOOLONG;
	else
		memcpy(name, found, n + 1);

	free(found);
	return ret;
}

void results_fork_prepare(void)
{
	pthread_mutex_lock(&result_lock);
}

void results_fork_parent(void)
{
	pthread_mutex_unlock(&result_lock);
}

void results_fork_child(void)
{
	pthread_mutex_unlock(&result_lock);
}
