#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

static pthread_mutex_t uplink_lock = PTHREAD_MUTEX_INITIALIZER;
static struct uplink **uplinks;
static size_t uplink_count;
static bool any_registered;

static bool prefix_match(const void *addr, const void *net,
			 unsigned int bits)
{
	const uint8_t *a = addr;
	const uint8_t *n = net;
	unsigned int bytes;
	uint8_t mask;

	bytes = bits / 8;
	if (memcmp(a, n, bytes))
		return false;

	if (!(bits % 8))
		return true;

	mask = (uint8_t)(0xff << (8 - bits % 8));
	return (a[bytes] & mask) == (n[bytes] & mask);
}

static const void *sockaddr_inaddr(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET)
		return &((const struct sockaddr_in *)ss)->sin_addr;

	return &((const struct sockaddr_in6 *)ss)->sin6_addr;
}

static void sockaddr_v4mapped_unmap(struct sockaddr_storage *ss)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in sin;

	if (ss->ss_family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
		return;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = sin6->sin6_port;
	memcpy(&sin.sin_addr, &sin6->sin6_addr.s6_addr[12], 4);
	memset(ss, 0, sizeof(*ss));
	memcpy(ss, &sin, sizeof(sin));
}

static bool sockaddr_is_specific(const struct sockaddr_storage *ss)
{
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
	const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;

	if (ss->ss_family == AF_INET)
		return sin->sin_addr.s_addr != htonl(INADDR_ANY);

	if (ss->ss_family == AF_INET6)
		return !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr);

	return false;
}

static bool uplink_contains(const struct uplink *up,
			    const struct sockaddr_storage *ss)
{
	if (up->family != ss->ss_family)
		return false;

	if (up->family == AF_INET)
		return prefix_match(sockaddr_inaddr(ss), &up->addr4,
				    up->prefix_len);

	return prefix_match(sockaddr_inaddr(ss), &up->addr6, up->prefix_len);
}

static bool ifname_valid(const char *key)
{
	size_t len;

	len = strlen(key);
	if (!len || len >= IF_NAMESIZE)
		return false;

	return !strpbrk(key, "/;:, \t");
}

static int uplink_key_parse(struct uplink *up, const char *key)
{
	char addr[INET6_ADDRSTRLEN];
	unsigned long bits;
	const char *slash;
	size_t len;
	char *end;

	slash = strchr(key, '/');
	len = slash ? (size_t)(slash - key) : strlen(key);
	if (len < sizeof(addr)) {
		memcpy(addr, key, len);
		addr[len] = '\0';
		if (inet_pton(AF_INET, addr, &up->addr4) == 1) {
			up->family = AF_INET;
			up->prefix_len = 32;
		} else if (inet_pton(AF_INET6, addr, &up->addr6) == 1) {
			up->family = AF_INET6;
			up->prefix_len = 128;
		}
	}

	if (up->family == AF_UNSPEC) {
		if (slash || !ifname_valid(key))
			return -EINVAL;

		strcpy(up->ifname, key);
		return 0;
	}

	if (!slash)
		return 0;

	errno = 0;
	bits = strtoul(slash + 1, &end, 10);
	if (errno || *end || end == slash + 1 || bits > up->prefix_len)
		return -EINVAL;

	up->prefix_len = (unsigned int)bits;
	return 0;
}

static struct uplink *uplink_find_locked(const char *key)
{
	size_t i;

	for (i = 0; i < uplink_count; i++) {
		if (!strcmp(uplinks[i]->key, key))
			return uplinks[i];
	}

	return NULL;
}

static int uplink_servers_replace(struct uplink *up, const char *servers)
{
	char *copy;

	copy = strdup(servers);
	if (!copy)
		return -ENOMEM;

	free(up->servers);
	up->servers = copy;
	if (up->channel)
		resolver_servers_set(up);

	return 0;
}

static struct uplink *uplink_insert_locked(const struct uplink *parsed,
					   const char *key,
					   const char *servers,
					   bool registered)
{
	struct uplink **grown;
	struct uplink *up;

	grown = realloc(uplinks, (uplink_count + 1) * sizeof(*uplinks));
	if (!grown)
		return NULL;

	uplinks = grown;
	up = malloc(sizeof(*up));
	if (!up)
		return NULL;

	*up = *parsed;
	up->key = strdup(key);
	up->servers = servers ? strdup(servers) : NULL;
	if (!up->key || (servers && !up->servers)) {
		free(up->servers);
		free(up->key);
		free(up);
		return NULL;
	}

	up->channel = NULL;
	up->registered = registered;
	up->id = (int)uplink_count;
	uplinks[uplink_count++] = up;

	return up;
}

static int uplink_add(const struct uplink *parsed, const char *key,
		      const char *servers, bool registered)
{
	struct uplink *up;
	int ret;

	pthread_mutex_lock(&uplink_lock);

	up = uplink_find_locked(key);
	if (!up) {
		up = uplink_insert_locked(parsed, key, servers, registered);
		ret = up ? up->id : -ENOMEM;
		goto out;
	}

	ret = up->id;
	if (servers && (!up->servers || strcmp(up->servers, servers))) {
		ret = uplink_servers_replace(up, servers);
		if (!ret)
			ret = up->id;
	}

	if (registered && ret >= 0)
		up->registered = true;

out:
	if (ret >= 0 && registered)
		__atomic_store_n(&any_registered, true, __ATOMIC_RELEASE);

	pthread_mutex_unlock(&uplink_lock);
	return ret;
}

int uplink_parse_add(const char *spec, bool registered)
{
	const char *servers = NULL;
	struct uplink parsed;
	char *save = NULL;
	char *copy;
	char *opt;
	char *key;
	int ret;

	memset(&parsed, 0, sizeof(parsed));
	parsed.family = AF_UNSPEC;

	copy = strdup(spec);
	if (!copy)
		return -ENOMEM;

	key = strtok_r(copy, ";", &save);
	ret = key ? uplink_key_parse(&parsed, key) : -EINVAL;
	if (ret)
		goto out;

	for (opt = strtok_r(NULL, ";", &save); opt;
	     opt = strtok_r(NULL, ";", &save)) {
		if (strncmp(opt, "dns=", 4) || !opt[4] || servers) {
			ret = -EINVAL;
			goto out;
		}
		servers = opt + 4;
	}

	ret = uplink_add(&parsed, key, servers, registered);

out:
	free(copy);
	return ret;
}

struct uplink *uplink_by_id(int id)
{
	struct uplink *up = NULL;

	pthread_mutex_lock(&uplink_lock);
	if (id >= 0 && (size_t)id < uplink_count && uplinks[id]->registered)
		up = uplinks[id];
	pthread_mutex_unlock(&uplink_lock);

	return up;
}

bool uplink_any_registered(void)
{
	return __atomic_load_n(&any_registered, __ATOMIC_ACQUIRE);
}

static struct uplink *uplink_by_ifname(const char *ifname)
{
	struct uplink parsed;
	struct uplink *up;
	size_t i;

	pthread_mutex_lock(&uplink_lock);

	for (i = 0; i < uplink_count; i++) {
		up = uplinks[i];
		if (up->family == AF_UNSPEC && !strcmp(up->ifname, ifname))
			goto out;
	}

	memset(&parsed, 0, sizeof(parsed));
	parsed.family = AF_UNSPEC;
	strcpy(parsed.ifname, ifname);
	up = uplink_insert_locked(&parsed, ifname, NULL, false);

out:
	pthread_mutex_unlock(&uplink_lock);
	return up;
}

static bool address_ifname_get(const struct sockaddr_storage *ss,
			       char *ifname)
{
	const struct sockaddr_storage *ifa_ss;
	struct ifaddrs *ifas;
	struct ifaddrs *ifa;
	bool found = false;
	size_t len;

	if (getifaddrs(&ifas))
		return false;

	len = ss->ss_family == AF_INET ? sizeof(struct in_addr) :
					 sizeof(struct in6_addr);
	for (ifa = ifas; ifa && !found; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != ss->ss_family)
			continue;

		ifa_ss = (const struct sockaddr_storage *)ifa->ifa_addr;
		if (memcmp(sockaddr_inaddr(ifa_ss), sockaddr_inaddr(ss), len))
			continue;

		snprintf(ifname, IF_NAMESIZE, "%s", ifa->ifa_name);
		found = true;
	}

	freeifaddrs(ifas);
	return found;
}

static struct uplink *uplink_prefix_best_locked(const struct sockaddr_storage *ss)
{
	struct uplink *best = NULL;
	struct uplink *up;
	size_t i;

	for (i = 0; i < uplink_count; i++) {
		up = uplinks[i];
		if (!uplink_contains(up, ss))
			continue;

		if (!best || up->prefix_len > best->prefix_len)
			best = up;
	}

	return best;
}

static struct uplink *uplink_registered_ifname_locked(const char *ifname)
{
	size_t i;

	for (i = 0; i < uplink_count; i++) {
		if (uplinks[i]->registered && uplinks[i]->family == AF_UNSPEC &&
		    !strcmp(uplinks[i]->ifname, ifname))
			return uplinks[i];
	}

	return NULL;
}

static struct uplink *uplink_by_address(struct sockaddr_storage *ss)
{
	char ifname[IF_NAMESIZE] = "";
	char key[INET6_ADDRSTRLEN];
	struct uplink parsed;
	struct uplink *up;
	bool owned;

	sockaddr_v4mapped_unmap(ss);
	owned = address_ifname_get(ss, ifname);
	if (!inet_ntop(ss->ss_family, sockaddr_inaddr(ss), key, sizeof(key)))
		return NULL;

	pthread_mutex_lock(&uplink_lock);

	up = uplink_prefix_best_locked(ss);
	if (up)
		goto out;

	if (owned) {
		up = uplink_registered_ifname_locked(ifname);
		if (up)
			goto out;
	}

	memset(&parsed, 0, sizeof(parsed));
	parsed.family = ss->ss_family;
	if (parsed.family == AF_INET) {
		memcpy(&parsed.addr4, sockaddr_inaddr(ss), sizeof(parsed.addr4));
		parsed.prefix_len = 32;
	} else {
		memcpy(&parsed.addr6, sockaddr_inaddr(ss), sizeof(parsed.addr6));
		parsed.prefix_len = 128;
	}
	up = uplink_insert_locked(&parsed, key, NULL, false);

out:
	pthread_mutex_unlock(&uplink_lock);
	return up;
}

struct uplink *uplink_of_socket(int fd)
{
	struct sockaddr_storage ss;
	char dev[IF_NAMESIZE + 1];
	socklen_t len;

	memset(dev, 0, sizeof(dev));
	len = sizeof(dev) - 1;
	if (!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) && len &&
	    dev[0])
		return uplink_by_ifname(dev);

	memset(&ss, 0, sizeof(ss));
	len = sizeof(ss);
	if (getsockname(fd, (struct sockaddr *)&ss, &len) ||
	    !sockaddr_is_specific(&ss))
		return NULL;

	return uplink_by_address(&ss);
}

bool uplink_source_get(const struct uplink *up, int family,
		       struct sockaddr_storage *ss)
{
	struct ifaddrs *ifas;
	struct ifaddrs *ifa;
	bool found = false;

	if (up->family != family)
		return false;

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = family;
	if (family == AF_INET)
		memcpy(&((struct sockaddr_in *)ss)->sin_addr, &up->addr4,
		       sizeof(up->addr4));
	else
		memcpy(&((struct sockaddr_in6 *)ss)->sin6_addr, &up->addr6,
		       sizeof(up->addr6));

	if (up->prefix_len == (family == AF_INET ? 32u : 128u))
		return true;

	if (getifaddrs(&ifas))
		return false;

	for (ifa = ifas; ifa && !found; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != family)
			continue;

		memset(ss, 0, sizeof(*ss));
		memcpy(ss, ifa->ifa_addr, family == AF_INET ?
		       sizeof(struct sockaddr_in) :
		       sizeof(struct sockaddr_in6));
		found = uplink_contains(up, ss);
	}

	freeifaddrs(ifas);
	return found;
}

bool uplink_family_usable(const struct uplink *up, int family)
{
	const struct sockaddr_in6 *sin6;
	struct ifaddrs *ifas;
	struct ifaddrs *ifa;
	bool found = false;

	if (up->family != AF_UNSPEC)
		return up->family == family;

	if (getifaddrs(&ifas))
		return false;

	for (ifa = ifas; ifa && !found; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != family ||
		    strcmp(ifa->ifa_name, up->ifname))
			continue;

		sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
		found = family == AF_INET ||
			!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr);
	}

	freeifaddrs(ifas);
	return found;
}

struct uplink **uplink_channels_get(size_t *count)
{
	struct uplink **list;
	size_t i;

	*count = 0;
	pthread_mutex_lock(&uplink_lock);

	list = malloc((uplink_count ? uplink_count : 1) * sizeof(*list));
	for (i = 0; list && i < uplink_count; i++) {
		if (uplinks[i]->channel)
			list[(*count)++] = uplinks[i];
	}

	pthread_mutex_unlock(&uplink_lock);
	return list;
}

bool uplink_system_servers(struct uplink *up)
{
	bool system;

	pthread_mutex_lock(&uplink_lock);
	system = !up->servers;
	pthread_mutex_unlock(&uplink_lock);

	return system;
}

int uplink_channel_ensure(struct uplink *up)
{
	int ret = 0;

	pthread_mutex_lock(&uplink_lock);
	if (!up->channel)
		ret = resolver_channel_create(up);
	pthread_mutex_unlock(&uplink_lock);

	return ret;
}

void uplink_lock_fork_prepare(void)
{
	pthread_mutex_lock(&uplink_lock);
}

void uplink_lock_fork_parent(void)
{
	pthread_mutex_unlock(&uplink_lock);
}

void uplink_lock_fork_child(void)
{
	size_t i;

	for (i = 0; i < uplink_count; i++)
		uplinks[i]->channel = NULL;

	pthread_mutex_unlock(&uplink_lock);
}
