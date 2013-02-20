/* Apache plugin for collectd using the scoreboard file
 */

#include "collectd.h"
#include "common.h"

#include <string.h>

/* Otherwise we get conflicts... */
#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING

#include "httpd.h"
#include "scoreboard.h"

static const char *config_keys[] = {
	"ScoreboardFile",
};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static const char *type_instance[SERVER_NUM_STATUS] = {
	"open",
	"starting",
	"waiting",
	"reading",
	"sending",
	"keepalive",
	"logging",
	"dnslookup",
	"closing",
	"finishing",
	"idle_cleanup",
};

char		*scoreboard_file = NULL;
apr_pool_t	*pool;

static void
submit_value(const char *type, const char *type_instance, value_t value)
{
	value_list_t vl = VALUE_LIST_INIT;

	vl.values = &value;
	vl.values_len = 1;

	sstrncpy (vl.host, hostname_g, sizeof (vl.host));
	sstrncpy (vl.plugin, "apache_scoreboard", sizeof (vl.plugin));
	sstrncpy (vl.type, type, sizeof (vl.type));
	if (type_instance != NULL)
		sstrncpy (vl.type_instance, type_instance,
				sizeof (vl.type_instance));

	plugin_dispatch_values (&vl);
}

static void
submit_derive(const char *type, const char *type_instance, derive_t c)
{
	value_t v;
	v.derive = c;
	submit_value(type, type_instance, v);
}

static void
submit_gauge(const char *type, const char *type_instance, gauge_t g)
{
	value_t v;
	v.gauge = g;
	submit_value(type, type_instance, v);
}

static int
scoreboard_init(void)
{
	apr_status_t	 rv;
	char		 errbuf[256];

	apr_initialize();

	if ((rv = apr_pool_create(&pool, NULL)) != APR_SUCCESS) {
		ERROR("apache_scoreboard plugin: apr_pool_create() - %s",
		    apr_strerror(rv, errbuf, sizeof(errbuf)));
		return (-1);
	}

	return (0);
}

static int
scoreboard_read(void)
{
	apr_status_t	 rv;
	apr_shm_t	*shm;
	char		 errbuf[256];
	void		*p;
	size_t		 size;
	global_score	*global;
	process_score	*parent;
	worker_score	*server;
	int		 i, j;
	long long	 status[SERVER_NUM_STATUS];
	long long	 busy = 0;
	long long	 ready = 0;
	unsigned long	 count = 0;
	apr_off_t	 bytes = 0;

	if ((rv = apr_shm_attach(&shm, scoreboard_file, pool)) != APR_SUCCESS) {
		/* If Apache is stopped, this will need handling better */
		ERROR("apache_scoreboard plugin: apr_shm_attach() - %s",
		    apr_strerror(rv, errbuf, sizeof(errbuf)));
		return (-1);
	}

	if (!(p = apr_shm_baseaddr_get(shm))) {
		ERROR("apache_scoreboard plugin: apr_shm_baseaddr_get() - failed");
		return (-1);
	}

	if ((size = apr_shm_size_get(shm)) < sizeof(*global)) {
		ERROR("apache_scoreboard plugin: apr_shm_size_get() - too small");
		return (-1);
	}

	global = p;
	p += sizeof(*global);

	parent = p;
	p += sizeof(*parent) * global->server_limit;

	memset(status, 0, sizeof(status));
	for (i = 0; i < global->server_limit; i++) {
		for (j = 0; j < global->thread_limit; j++) {
			server = p;
			p += sizeof(*server);
			/* Shouldn't happen */
			if (server->status >= SERVER_NUM_STATUS)
				continue;
			status[server->status]++;
			if (parent[i].quiescing || !parent[i].pid) continue;
			/* Track busy connections */
			if (server->status == SERVER_READY) {
				ready++;
			} else if (server->status != SERVER_DEAD
			    && server->status != SERVER_STARTING
			    && server->status != SERVER_IDLE_KILL)
				busy++;
			count += server->access_count;
			bytes += server->bytes_served;
		}
	}

	if ((rv = apr_shm_detach(shm)) != APR_SUCCESS) {
		ERROR("apache_scoreboard plugin: apr_shm_detach() - %s",
		    apr_strerror(rv, errbuf, sizeof(errbuf)));
		return (-1);
	}

	/* Submit values */
	for (i = 0; i < SERVER_NUM_STATUS; i++)
		submit_gauge("apache_scoreboard", type_instance[i], status[i]);

	submit_derive("apache_requests", NULL, count);
	submit_derive("apache_bytes", NULL, bytes);
	submit_gauge("apache_connections", NULL, busy);
	submit_gauge("apache_idle_workers", NULL, ready);

	return (0);
}

static int
scoreboard_config(const char *key, const char *value)
{
	if (strcasecmp ("ScoreboardFile", key) == 0) {
		if (scoreboard_file != NULL)
			free(scoreboard_file);
		if ((scoreboard_file = strdup(value)) == NULL)
			return (-1);
		plugin_register_init("apache_scoreboard", scoreboard_init);
		plugin_register_read("apache_scoreboard", scoreboard_read);
	} else {
		return (-1);
	}

	return (0);
}

void
module_register(void)
{
	plugin_register_config("apache_scoreboard", scoreboard_config,
	    config_keys, config_keys_num);
}
