#ifndef UPLINKDNS_INTERNAL_H
#define UPLINKDNS_INTERNAL_H

#include <ares.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define UPLINKDNS_EXPORT __attribute__((visibility("default")))

struct uplink {
	char ifname[IF_NAMESIZE];
	struct in6_addr addr6;
	struct in_addr addr4;
	ares_channel_t *channel;
	unsigned int prefix_len;
	bool registered;
	char *servers;
	char *key;
	int family;
	int id;
};

struct real_funcs {
	int (*getaddrinfo)(const char *node, const char *service,
			   const struct addrinfo *hints,
			   struct addrinfo **res);
	void (*freeaddrinfo)(struct addrinfo *res);
	int (*getnameinfo)(const struct sockaddr *sa, socklen_t salen,
			   char *host, socklen_t hostlen, char *serv,
			   socklen_t servlen, int flags);
	int (*connect)(int fd, const struct sockaddr *sa, socklen_t salen);
	int (*bind)(int fd, const struct sockaddr *sa, socklen_t salen);
	ssize_t (*sendto)(int fd, const void *buf, size_t len, int flags,
			  const struct sockaddr *sa, socklen_t salen);
	ssize_t (*sendmsg)(int fd, const struct msghdr *msg, int flags);
};

struct addr_list {
	struct sockaddr_storage *addrs;
	size_t count;
};

extern struct real_funcs real;
extern bool debug_enabled;

void real_init(void);
void debug_log(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

int context_get(void);
void results_fork_prepare(void);
void results_fork_parent(void);
void results_fork_child(void);

int uplink_parse_add(const char *spec, bool registered);
struct uplink *uplink_by_id(int id);
struct uplink *uplink_of_socket(int fd);
bool uplink_any_registered(void);
bool uplink_source_get(const struct uplink *up, int family,
		       struct sockaddr_storage *ss);
bool uplink_family_usable(const struct uplink *up, int family);
struct uplink **uplink_channels_get(size_t *count);
bool uplink_system_servers(struct uplink *up);
int uplink_channel_ensure(struct uplink *up);
void uplink_lock_fork_prepare(void);
void uplink_lock_fork_parent(void);
void uplink_lock_fork_child(void);

int resolver_lookup(struct uplink *up, const char *name, int family,
		    struct addr_list *list, char **canon);
int resolver_channel_create(struct uplink *up);
void resolver_servers_set(struct uplink *up);
void resolver_fork_prepare(void);
void resolver_fork_parent(void);
void resolver_fork_child(void);

int system_lookup(const char *name, int family, struct addr_list *list,
		  char **canon);
void addr_list_free(struct addr_list *list);

enum synth_slot {
	SYNTH_SLOT_AAAA,
	SYNTH_SLOT_A,
	SYNTH_SLOTS,
};

bool synth_is_candidate(const struct sockaddr *sa, socklen_t salen);
int synth_name_assign(const char *name, struct in_addr *v4,
		      struct in6_addr *v6_aaaa, struct in6_addr *v6_a);
char *synth_name_get(const struct sockaddr *sa, enum synth_slot *slot,
		     unsigned int *rotation);
void synth_fork_prepare(void);
void synth_fork_parent(void);
void synth_fork_child(void);

#endif
