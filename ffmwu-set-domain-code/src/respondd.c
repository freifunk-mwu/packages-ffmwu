#include <respondd.h>

#include <json-c/json.h>
#include <libgluonutil.h>

#include <uci.h>

static struct json_object * get_system_domain_code(void) {
	struct uci_context *ctx = uci_alloc_context();
	if (!ctx)
		return NULL;
	ctx->flags &= ~UCI_FLAG_STRICT;

	struct uci_package *p;
	if (uci_load(ctx, "gluon", &p))
		goto error;

	struct uci_section *s = uci_lookup_section(ctx, p, "system");
	if (!s)
		goto error;

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "domain_code", gluonutil_wrap_string(uci_lookup_option_string(ctx, s, "domain_code")));

	uci_free_context(ctx);
	return ret;

 error:
	uci_free_context(ctx);
	return NULL;
}

static struct json_object * respondd_provider_nodeinfo() {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "system", get_system_domain_code());

	return ret;
}

const struct respondd_provider_info respondd_providers[] = {
	{"nodeinfo", respondd_provider_nodeinfo},
	{}
};
