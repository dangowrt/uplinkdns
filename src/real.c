#define _GNU_SOURCE

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

struct real_funcs real;
bool debug_enabled;

static pthread_once_t real_once = PTHREAD_ONCE_INIT;

static void *real_symbol(const char *name)
{
	void *sym;

	sym = dlsym(RTLD_NEXT, name);
	if (!sym) {
		fprintf(stderr, "uplinkdns: %s not found: %s\n", name,
			dlerror());
		abort();
	}

	return sym;
}

void *real_optional(const char *name, const char *compat)
{
	void *sym;

	sym = dlsym(RTLD_NEXT, name);
	if (!sym && compat)
		sym = dlsym(RTLD_NEXT, compat);

	return sym;
}

static void fork_prepare(void)
{
	uplink_lock_fork_prepare();
	resolver_fork_prepare();
	synth_fork_prepare();
	results_fork_prepare();
}

static void fork_parent(void)
{
	results_fork_parent();
	synth_fork_parent();
	resolver_fork_parent();
	uplink_lock_fork_parent();
}

static void fork_child(void)
{
	results_fork_child();
	synth_fork_child();
	resolver_fork_child();
	uplink_lock_fork_child();
}

static void env_uplinks_add(void)
{
	const char *env;
	char *specs;
	char *save;
	char *spec;

	env = getenv("UPLINKDNS_UPLINKS");
	if (!env || !*env)
		return;

	specs = strdup(env);
	if (!specs)
		return;

	for (spec = strtok_r(specs, " \t\n", &save); spec;
	     spec = strtok_r(NULL, " \t\n", &save)) {
		if (uplink_parse_add(spec, true) < 0)
			fprintf(stderr, "uplinkdns: invalid uplink '%s'\n",
				spec);
	}

	free(specs);
}

static void real_once_init(void)
{
	const char *env;

	real.getaddrinfo = real_symbol("getaddrinfo");
	real.freeaddrinfo = real_symbol("freeaddrinfo");
	real.getnameinfo = real_symbol("getnameinfo");
	real.connect = real_symbol("connect");
	real.bind = real_symbol("bind");
	real.sendto = real_symbol("sendto");
	real.sendmsg = real_symbol("sendmsg");
	real.sendmmsg = real_symbol("sendmmsg");
	real.gethostbyname = real_symbol("gethostbyname");
	real.gethostbyname2 = real_symbol("gethostbyname2");
	real.gethostbyname_r = real_symbol("gethostbyname_r");
	real.gethostbyname2_r = real_symbol("gethostbyname2_r");
	real.gethostbyaddr = real_symbol("gethostbyaddr");
	real.gethostbyaddr_r = real_symbol("gethostbyaddr_r");
	real.res_query = real_optional("res_query", "__res_query");
	real.res_search = real_optional("res_search", "__res_search");
	real.res_querydomain = real_optional("res_querydomain",
					     "__res_querydomain");
	real.res_send = real_optional("res_send", "__res_send");
	real.res_nquery = real_optional("res_nquery", "__res_nquery");
	real.res_nsearch = real_optional("res_nsearch", "__res_nsearch");
	real.res_nquerydomain = real_optional("res_nquerydomain",
					      "__res_nquerydomain");
	real.res_nsend = real_optional("res_nsend", "__res_nsend");

	env = getenv("UPLINKDNS_DEBUG");
	debug_enabled = env && *env && *env != '0';

	ares_library_init(ARES_LIB_INIT_ALL);
	pthread_atfork(fork_prepare, fork_parent, fork_child);
	env_uplinks_add();
}

void real_init(void)
{
	pthread_once(&real_once, real_once_init);
}

void debug_log(const char *fmt, ...)
{
	va_list ap;

	if (!debug_enabled)
		return;

	va_start(ap, fmt);
	fputs("uplinkdns: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}
