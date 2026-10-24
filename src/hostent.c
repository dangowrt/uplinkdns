#define _GNU_SOURCE

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

struct hostent_slot {
	struct hostent he;
	size_t len;
	char *buf;
};

static pthread_once_t slot_once = PTHREAD_ONCE_INIT;
static pthread_key_t slot_key;
static bool slot_key_valid;

static void slot_free(void *data)
{
	struct hostent_slot *slot = data;

	free(slot->buf);
	free(slot);
}

static void slot_key_create(void)
{
	slot_key_valid = !pthread_key_create(&slot_key, slot_free);
}

static struct hostent_slot *slot_get(void)
{
	struct hostent_slot *slot;

	pthread_once(&slot_once, slot_key_create);
	if (!slot_key_valid)
		return NULL;

	slot = pthread_getspecific(slot_key);
	if (slot)
		return slot;

	slot = calloc(1, sizeof(*slot));
	if (slot && pthread_setspecific(slot_key, slot)) {
		free(slot);
		slot = NULL;
	}

	return slot;
}

static size_t family_addrlen(int af)
{
	return af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
}

static size_t hostent_size(const char *name, int af, size_t count)
{
	return sizeof(char *) - 1 + (count + 2) * sizeof(char *) +
	       count * family_addrlen(af) + strlen(name) + 1;
}

static int hostent_fill(struct hostent *he, char *buf, size_t buflen,
			const char *name, int af, const void *const *addrs,
			size_t count)
{
	uintptr_t misalign;
	size_t addrlen;
	char **ptrs;
	size_t need;
	size_t pad;
	size_t i;
	char *p;

	addrlen = family_addrlen(af);
	misalign = (uintptr_t)buf % sizeof(char *);
	pad = misalign ? sizeof(char *) - misalign : 0;
	need = pad + (count + 2) * sizeof(char *) + count * addrlen +
	       strlen(name) + 1;
	if (need > buflen)
		return ERANGE;

	ptrs = (char **)(void *)(buf + pad);
	p = (char *)(ptrs + count + 2);
	ptrs[0] = NULL;
	for (i = 0; i < count; i++) {
		memcpy(p, addrs[i], addrlen);
		ptrs[i + 1] = p;
		p += addrlen;
	}
	ptrs[count + 1] = NULL;
	strcpy(p, name);

	he->h_name = p;
	he->h_aliases = ptrs;
	he->h_addrtype = af;
	he->h_length = (int)addrlen;
	he->h_addr_list = ptrs + 1;
	return 0;
}

static int hostent_store(struct hostent *he, char *buf, size_t buflen,
			 struct hostent_slot *slot, const char *name, int af,
			 const void *const *addrs, size_t count)
{
	size_t need;
	char *grown;

	if (!slot)
		return hostent_fill(he, buf, buflen, name, af, addrs, count);

	need = hostent_size(name, af, count);
	if (slot->len < need) {
		grown = realloc(slot->buf, need);
		if (!grown)
			return ENOMEM;

		slot->buf = grown;
		slot->len = need;
	}

	return hostent_fill(&slot->he, slot->buf, slot->len, name, af, addrs,
			    count);
}

static int eai_herrno(int eai)
{
	switch (eai) {
	case EAI_NONAME:
		return HOST_NOT_FOUND;
	case EAI_AGAIN:
		return TRY_AGAIN;
	default:
		return NO_RECOVERY;
	}
}

static int eai_ret(int eai)
{
	switch (eai) {
	case EAI_NONAME:
		return ENOENT;
	case EAI_AGAIN:
		return EAGAIN;
	case EAI_MEMORY:
		return ENOMEM;
	case EAI_SYSTEM:
		return errno;
	default:
		return EBADMSG;
	}
}

static int store_ret(int ret, int *err)
{
	if (!ret)
		return 0;

	*err = NO_RECOVERY;
#ifdef NETDB_INTERNAL
	if (ret == ERANGE)
		*err = NETDB_INTERNAL;
#endif
	errno = ret;
	return ret;
}

static const void **forward_addrs(const struct addrinfo *res, int af,
				  size_t *count)
{
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_in *sin;
	const struct addrinfo *ai;
	const void **addrs;
	size_t n = 0;

	*count = 0;
	for (ai = res; ai; ai = ai->ai_next)
		n += ai->ai_family == af;

	addrs = malloc((n ? n : 1) * sizeof(*addrs));
	if (!addrs)
		return NULL;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family != af)
			continue;

		sin = (const struct sockaddr_in *)ai->ai_addr;
		sin6 = (const struct sockaddr_in6 *)ai->ai_addr;
		addrs[(*count)++] = af == AF_INET ? (const void *)&sin->sin_addr :
						    (const void *)&sin6->sin6_addr;
	}

	return addrs;
}

static int forward_hostent(const char *name, int af, struct hostent *he,
			   char *buf, size_t buflen, struct hostent_slot *slot,
			   struct hostent **result, int *err)
{
	struct addrinfo hints;
	struct addrinfo *res;
	const void **addrs;
	size_t count;
	int ret;

	*result = NULL;
	if (af != AF_INET && af != AF_INET6) {
		*err = NO_RECOVERY;
		return EAFNOSUPPORT;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;
	ret = addrinfo_resolve(context_get(), name, NULL, &hints, &res);
	if (ret) {
		*err = eai_herrno(ret);
		return eai_ret(ret);
	}

	addrs = forward_addrs(res, af, &count);
	ret = addrs ? hostent_store(he, buf, buflen, slot,
				    res->ai_canonname ? res->ai_canonname : name,
				    af, addrs, count) :
		      ENOMEM;
	free(addrs);
	addrinfo_release(res);
	if (store_ret(ret, err))
		return ret;

	*result = slot ? &slot->he : he;
	return 0;
}

static socklen_t sockaddr_build(struct sockaddr_storage *ss, const void *addr,
				socklen_t len, int type)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	memset(ss, 0, sizeof(*ss));
	if (type == AF_INET && len == sizeof(sin->sin_addr)) {
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, addr, len);
		return sizeof(*sin);
	}

	if (type == AF_INET6 && len == sizeof(sin6->sin6_addr)) {
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, addr, len);
		return sizeof(*sin6);
	}

	return 0;
}

static bool reverse_name(const void *addr, socklen_t len, int type,
			 char **name, int *eai)
{
	struct sockaddr_storage ss;
	enum synth_slot synth;
	struct uplink *up;
	socklen_t salen;

	*name = NULL;
	*eai = 0;
	salen = sockaddr_build(&ss, addr, len, type);
	if (!salen)
		return false;

	if (synth_is_candidate((struct sockaddr *)&ss, salen))
		*name = synth_name_get((struct sockaddr *)&ss, &synth, NULL);
	if (*name)
		return true;

	up = context_uplink();
	if (!up)
		return false;

	*eai = resolver_reverse(up, (struct sockaddr *)&ss, salen, false,
				name);
	return true;
}

static int reverse_hostent(const void *addr, int type, const char *name,
			   int eai, struct hostent *he, char *buf,
			   size_t buflen, struct hostent_slot *slot,
			   struct hostent **result, int *err)
{
	const void *addrs[1];
	int ret;

	*result = NULL;
	if (eai) {
		*err = eai_herrno(eai);
		return eai_ret(eai);
	}

	addrs[0] = addr;
	ret = hostent_store(he, buf, buflen, slot, name, type, addrs, 1);
	if (store_ret(ret, err))
		return ret;

	*result = slot ? &slot->he : he;
	return 0;
}

UPLINKDNS_EXPORT int gethostbyname2_r(const char *name, int af,
				      struct hostent *he, char *buf,
				      size_t buflen, struct hostent **result,
				      int *err)
{
	real_init();
	if (addrinfo_bypass(context_get(), name, NULL))
		return real.gethostbyname2_r(name, af, he, buf, buflen, result,
					     err);

	return forward_hostent(name, af, he, buf, buflen, NULL, result, err);
}

UPLINKDNS_EXPORT int gethostbyname_r(const char *name, struct hostent *he,
				     char *buf, size_t buflen,
				     struct hostent **result, int *err)
{
	real_init();
	if (addrinfo_bypass(context_get(), name, NULL))
		return real.gethostbyname_r(name, he, buf, buflen, result, err);

	return forward_hostent(name, AF_INET, he, buf, buflen, NULL, result,
			       err);
}

UPLINKDNS_EXPORT struct hostent *gethostbyname2(const char *name, int af)
{
	struct hostent_slot *slot;
	struct hostent *result;

	real_init();
	if (addrinfo_bypass(context_get(), name, NULL))
		return real.gethostbyname2(name, af);

	slot = slot_get();
	if (!slot) {
		h_errno = NO_RECOVERY;
		return NULL;
	}

	forward_hostent(name, af, NULL, NULL, 0, slot, &result, &h_errno);
	return result;
}

UPLINKDNS_EXPORT struct hostent *gethostbyname(const char *name)
{
	real_init();
	if (addrinfo_bypass(context_get(), name, NULL))
		return real.gethostbyname(name);

	return gethostbyname2(name, AF_INET);
}

UPLINKDNS_EXPORT int gethostbyaddr_r(const void *addr, socklen_t len, int type,
				     struct hostent *he, char *buf,
				     size_t buflen, struct hostent **result,
				     int *err)
{
	char *name;
	int eai;
	int ret;

	real_init();
	if (!reverse_name(addr, len, type, &name, &eai))
		return real.gethostbyaddr_r(addr, len, type, he, buf, buflen,
					    result, err);

	ret = reverse_hostent(addr, type, name, eai, he, buf, buflen, NULL,
			      result, err);
	free(name);
	return ret;
}

UPLINKDNS_EXPORT struct hostent *gethostbyaddr(const void *addr, socklen_t len,
					       int type)
{
	struct hostent_slot *slot;
	struct hostent *result;
	char *name;
	int eai;

	real_init();
	if (!reverse_name(addr, len, type, &name, &eai))
		return real.gethostbyaddr(addr, len, type);

	slot = slot_get();
	if (!slot) {
		free(name);
		h_errno = NO_RECOVERY;
		return NULL;
	}

	reverse_hostent(addr, type, name, eai, NULL, NULL, 0, slot, &result,
			&h_errno);
	free(name);
	return result;
}
