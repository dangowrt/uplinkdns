#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>

#include "internal.h"

/* RFC 2544 benchmarking network 198.18.0.0/15, RFC 6890 section 2.2.2 */
#define SYNTH_V4_NET		0xc6120000u
#define SYNTH_V4_PREFIX_LEN	15
#define SYNTH_V4_SIZE		(1u << (32 - SYNTH_V4_PREFIX_LEN))
/* RFC 4193 section 3.1: fd00::/8 plus a 40-bit random global ID */
#define SYNTH_V6_PREFIX_BYTES	6
#define SYNTH_V6_ULA_L		0xfd

struct synth_entry {
	unsigned int rotation[SYNTH_SLOTS];
	struct synth_entry *prev;
	struct synth_entry *next;
	uint32_t v4_index;
	uint64_t seq;
	char *name;
};

static pthread_mutex_t synth_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t v6_prefix[SYNTH_V6_PREFIX_BYTES];
static struct synth_entry **v4_table;
static struct synth_entry *lru_head;
static struct synth_entry *lru_tail;
static uint64_t seq_next = 1;
static uint32_t v4_next = 1;
static void *name_tree;
static void *seq_tree;
static bool v6_ready;

static int name_cmp(const void *a, const void *b)
{
	const struct synth_entry *ea = a;
	const struct synth_entry *eb = b;

	return strcasecmp(ea->name, eb->name);
}

static int seq_cmp(const void *a, const void *b)
{
	const struct synth_entry *ea = a;
	const struct synth_entry *eb = b;

	if (ea->seq == eb->seq)
		return 0;

	return ea->seq < eb->seq ? -1 : 1;
}

static void lru_unlink(struct synth_entry *e)
{
	if (e->prev)
		e->prev->next = e->next;
	else
		lru_head = e->next;

	if (e->next)
		e->next->prev = e->prev;
	else
		lru_tail = e->prev;

	e->prev = NULL;
	e->next = NULL;
}

static void lru_push(struct synth_entry *e)
{
	e->prev = NULL;
	e->next = lru_head;
	if (lru_head)
		lru_head->prev = e;
	else
		lru_tail = e;

	lru_head = e;
}

static void entry_touch(struct synth_entry *e)
{
	lru_unlink(e);
	lru_push(e);
}

static bool v6_prefix_init_locked(void)
{
	ssize_t ret;

	if (v6_ready)
		return true;

	do {
		ret = getrandom(v6_prefix, sizeof(v6_prefix), 0);
	} while (ret < 0 && errno == EINTR);

	if (ret != (ssize_t)sizeof(v6_prefix))
		return false;

	v6_prefix[0] = SYNTH_V6_ULA_L;
	__atomic_store_n(&v6_ready, true, __ATOMIC_RELEASE);
	return true;
}

static struct synth_entry *entry_recycle_locked(void)
{
	struct synth_entry *e = lru_tail;

	if (!e)
		return NULL;

	tdelete(e, &name_tree, name_cmp);
	tdelete(e, &seq_tree, seq_cmp);
	lru_unlink(e);
	free(e->name);
	e->name = NULL;

	return e;
}

static struct synth_entry *entry_alloc_locked(void)
{
	struct synth_entry *e;

	if (!v4_table) {
		v4_table = calloc(SYNTH_V4_SIZE, sizeof(*v4_table));
		if (!v4_table)
			return NULL;
	}

	/* callers treat all-zero and all-ones host parts as special */
	if (v4_next >= SYNTH_V4_SIZE - 1)
		return entry_recycle_locked();

	e = calloc(1, sizeof(*e));
	if (e)
		e->v4_index = v4_next++;

	return e;
}

static struct synth_entry *entry_create_locked(const char *name)
{
	struct synth_entry *e;
	char *copy;

	copy = strdup(name);
	if (!copy)
		return NULL;

	e = entry_alloc_locked();
	if (!e) {
		free(copy);
		return NULL;
	}

	memset(e->rotation, 0, sizeof(e->rotation));
	e->name = copy;
	e->seq = seq_next++;
	v4_table[e->v4_index] = e;

	if (!tsearch(e, &name_tree, name_cmp))
		goto fail;

	if (!tsearch(e, &seq_tree, seq_cmp)) {
		tdelete(e, &name_tree, name_cmp);
		goto fail;
	}

	lru_push(e);
	return e;

fail:
	v4_table[e->v4_index] = NULL;
	free(e->name);
	free(e);
	return NULL;
}

static void v4_fill(uint32_t index, struct in_addr *addr)
{
	addr->s_addr = htonl(SYNTH_V4_NET | index);
}

static void v6_fill(uint64_t seq, enum synth_slot slot,
		    struct in6_addr *addr)
{
	int i;

	memcpy(addr->s6_addr, v6_prefix, SYNTH_V6_PREFIX_BYTES);
	addr->s6_addr[6] = 0;
	addr->s6_addr[7] = (uint8_t)slot;
	for (i = 0; i < 8; i++)
		addr->s6_addr[15 - i] = (uint8_t)(seq >> (8 * i));
}

int synth_name_assign(const char *name, struct in_addr *v4,
		      struct in6_addr *v6_aaaa, struct in6_addr *v6_a)
{
	struct synth_entry **found;
	struct synth_entry key;
	struct synth_entry *e;
	int ret = 0;

	memset(&key, 0, sizeof(key));
	key.name = (char *)name;

	pthread_mutex_lock(&synth_lock);

	if (!v6_prefix_init_locked()) {
		ret = EAI_FAIL;
		goto out;
	}

	found = tfind(&key, &name_tree, name_cmp);
	if (found) {
		e = *found;
		entry_touch(e);
	} else {
		e = entry_create_locked(name);
		if (!e) {
			ret = EAI_MEMORY;
			goto out;
		}
	}

	v4_fill(e->v4_index, v4);
	v6_fill(e->seq, SYNTH_SLOT_AAAA, v6_aaaa);
	v6_fill(e->seq, SYNTH_SLOT_A, v6_a);

out:
	pthread_mutex_unlock(&synth_lock);
	return ret;
}

bool synth_is_candidate(const struct sockaddr *sa, socklen_t salen)
{
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_in *sin;

	if (!sa)
		return false;

	if (sa->sa_family == AF_INET && salen >= sizeof(*sin)) {
		sin = (const struct sockaddr_in *)sa;
		return (ntohl(sin->sin_addr.s_addr) & ~(SYNTH_V4_SIZE - 1)) ==
		       SYNTH_V4_NET;
	}

	if (sa->sa_family != AF_INET6 || salen < sizeof(*sin6) ||
	    !__atomic_load_n(&v6_ready, __ATOMIC_ACQUIRE))
		return false;

	sin6 = (const struct sockaddr_in6 *)sa;
	return !memcmp(sin6->sin6_addr.s6_addr, v6_prefix,
		       SYNTH_V6_PREFIX_BYTES);
}

static struct synth_entry *entry_by_v6_locked(const struct sockaddr_in6 *sin6,
					      enum synth_slot *slot)
{
	const uint8_t *bytes = sin6->sin6_addr.s6_addr;
	struct synth_entry **found;
	struct synth_entry key;
	int i;

	if (bytes[6] || bytes[7] >= SYNTH_SLOTS)
		return NULL;

	memset(&key, 0, sizeof(key));
	for (i = 8; i < 16; i++)
		key.seq = key.seq << 8 | bytes[i];

	found = tfind(&key, &seq_tree, seq_cmp);
	if (!found)
		return NULL;

	*slot = (enum synth_slot)bytes[7];
	return *found;
}

static struct synth_entry *entry_by_v4_locked(const struct sockaddr_in *sin,
					      enum synth_slot *slot)
{
	uint32_t index;

	if (!v4_table)
		return NULL;

	index = ntohl(sin->sin_addr.s_addr) & (SYNTH_V4_SIZE - 1);
	*slot = SYNTH_SLOT_A;
	return v4_table[index];
}

char *synth_name_get(const struct sockaddr *sa, enum synth_slot *slot,
		     unsigned int *rotation)
{
	struct synth_entry *e;
	char *name = NULL;

	pthread_mutex_lock(&synth_lock);

	if (sa->sa_family == AF_INET)
		e = entry_by_v4_locked((const struct sockaddr_in *)sa, slot);
	else
		e = entry_by_v6_locked((const struct sockaddr_in6 *)sa, slot);

	if (!e) {
		errno = ENOENT;
		goto out;
	}

	entry_touch(e);
	if (rotation)
		*rotation = e->rotation[*slot]++;

	name = strdup(e->name);
	if (!name)
		errno = ENOMEM;

out:
	pthread_mutex_unlock(&synth_lock);
	return name;
}

void synth_fork_prepare(void)
{
	pthread_mutex_lock(&synth_lock);
}

void synth_fork_parent(void)
{
	pthread_mutex_unlock(&synth_lock);
}

void synth_fork_child(void)
{
	pthread_mutex_unlock(&synth_lock);
}
