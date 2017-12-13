#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/limits.h>

#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "batadv-netlink.h"

#include "mac.h"

// Recheck TQs after this time even if no RA was received
#define MAX_INTERVAL 60

// Recheck TQs at most this often, even if new RAs were received (they won't
// become the preferred routers until the TQs have been rechecked)
// Also, the first update will take at least this long
#define MIN_INTERVAL 15

// max execution time of a single ebtables call in nanoseconds
#define EBTABLES_TIMEOUT 500000000 // 500ms

#define BUFSIZE 1500

#ifdef DEBUG
#define CHECK(stmt) \
    if(!(stmt)) { \
        fprintf(stderr, "check failed: " #stmt "\n"); \
        goto check_failed; \
    }
#define DEBUG_MSG(msg, ...) fprintf(stderr, msg "\n", ##__VA_ARGS__)
#else
#define CHECK(stmt) if(!(stmt)) goto check_failed;
#define DEBUG_MSG(msg, ...) do {} while(0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(A) (sizeof(A)/sizeof(A[0]))
#endif

#define foreach(item, list) \
	for(item = list; item != NULL; item = item->next)

struct router {
	struct router *next;
	struct ether_addr src;
	struct ether_addr originator;
	time_t eol;
	uint8_t tq;
};

struct global {
	int sock;
	struct router *routers;
	const char *iface;
	const char *mesh_iface;
	const char *chain;
	uint16_t max_tq;
	uint16_t hysteresis_thresh;
	struct router *best_router;
} G = {
	.iface = "br-client",
	.mesh_iface = "bat0",
};


static void error_message(int status, int errnum, char *message, ...) {
	va_list ap;
	va_start(ap, message);
	fflush(stdout);
	vfprintf(stderr, message, ap);
	if (errnum)
		fprintf(stderr, ": %s", strerror(errnum));
	fprintf(stderr, "\n");
	if (status)
		exit(status);
}

static void cleanup() {
	struct router *router;
	close(G.sock);

	while (G.routers != NULL) {
		router = G.routers;
		G.routers = router->next;
		free(router);
	}
}

static void usage(const char *msg) {
	if (msg != NULL && *msg != '\0') {
		fprintf(stderr, "ERROR: %s\n\n", msg);
	}
	fprintf(stderr,
		"Usage: %s [-m <mesh_iface>] [-t <thresh>] -c <chain> -i <iface>\n\n"
		"  -m <mesh_iface>  B.A.T.M.A.N. advanced mesh interface used to get metric\n"
		"                   information (\"TQ\") for the available gateways. Default: bat0\n"
		"  -t <thresh>      Minimum TQ difference required to switch the gateway.\n"
		"                   Default: 0\n"
		"  -c <chain>       ebtables chain that should be managed by the daemon. The\n"
		"                   chain already has to exist on program invocation and should\n"
		"                   have a DROP policy. It will be flushed by the program!\n"
		"  -i <iface>       Interface to listen on for router advertisements. Should be\n"
		"                   <mesh_iface> or a bridge on top of it, as no metric\n"
		"                   information will be available for hosts on other interfaces.\n\n",
		program_invocation_short_name);
	cleanup();
	if (msg == NULL)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}

#define exit_errmsg(message, ...) { \
	fprintf(stderr, message "\n", ##__VA_ARGS__); \
	cleanup(); \
	exit(1); \
	}

static inline void exit_errno(const char *message) {
	cleanup();
	error_message(1, errno, "error: %s", message);
}

static inline void warn_errno(const char *message) {
	error_message(0, errno, "warning: %s", message);
}

static int init_packet_socket(unsigned int ifindex) {
	struct sock_filter radv_filter_code[] = {
		// check that this is an ICMPv6 packet
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ICMPV6, 0, 7),
		// check that this is a router advertisement
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ND_ROUTER_ADVERT, 0, 5),
		// check that the code field in the ICMPv6 header is 0
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct nd_router_advert, nd_ra_code)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 3),
		// check that this is a default route (lifetime > 0)
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct nd_router_advert, nd_ra_router_lifetime)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
		// return true
		BPF_STMT(BPF_RET|BPF_K, 0xffffffff),
		// return false
		BPF_STMT(BPF_RET|BPF_K, 0),
	};

	struct sock_fprog radv_filter = {
		.len = ARRAY_SIZE(radv_filter_code),
		.filter = radv_filter_code,
	};

	int sock = socket(AF_PACKET, SOCK_DGRAM|SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if (sock < 0)
		exit_errno("can't open packet socket");
	int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &radv_filter, sizeof(radv_filter));
	if (ret < 0)
		exit_errno("can't attach socket filter");

	struct sockaddr_ll bind_iface = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IPV6),
		.sll_ifindex = ifindex,
	};
	bind(sock, (struct sockaddr *)&bind_iface, sizeof(bind_iface));

	return sock;
}

char *ether_ntoa_long(const struct ether_addr *addr)
{
	static char asc[F_MAC_LEN + 1];

	sprintf(asc, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr->ether_addr_octet[0], addr->ether_addr_octet[1],
		addr->ether_addr_octet[2], addr->ether_addr_octet[3],
		addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

	return asc;
}

struct find_originator_netlink_opts {
	struct ether_addr mac;
	bool found;
	struct batadv_nlquery_opts query_opts;
};

static const enum batadv_nl_attrs find_originator_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_ORIG_ADDRESS,
};

static int find_originator_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct find_originator_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	uint8_t *addr;
	uint8_t *orig;

	opts = container_of(query_opts, struct find_originator_netlink_opts,
				query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_GLOBAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
			genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (batadv_nl_missing_attrs(attrs, find_originator_mandatory,
					ARRAY_SIZE(find_originator_mandatory)))
		return NL_OK;

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	if (memcmp(&opts->mac, addr, ETH_ALEN) != 0)
		return NL_OK;

	memcpy(&opts->mac, orig, ETH_ALEN);
	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int find_originator(const char *mesh_iface, const struct ether_addr *mac,
			struct ether_addr *mac_out)
{
	struct find_originator_netlink_opts opts = {
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	memcpy(&opts.mac, mac, ETH_ALEN);

	ret = batadv_nl_query_common(mesh_iface,
					BATADV_CMD_GET_TRANSTABLE_GLOBAL,
					find_originator_netlink_cb, NLM_F_DUMP,
					&opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	memcpy(mac_out, &opts.mac, ETH_ALEN);

	return 0;
}

struct find_tq_netlink_opts {
	struct ether_addr mac;
	uint8_t tq;
	bool found;
	struct batadv_nlquery_opts query_opts;
};

static const enum batadv_nl_attrs find_tq_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_TQ,
};

static int find_tq_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct find_tq_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	uint8_t *orig;
	uint8_t *tq;

	opts = container_of(query_opts, struct find_tq_netlink_opts,
				query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
			genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (batadv_nl_missing_attrs(attrs, find_tq_mandatory,
					ARRAY_SIZE(find_tq_mandatory)))
		return NL_OK;

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	tq = nla_data(attrs[BATADV_ATTR_TQ]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	if (memcmp(&opts->mac, orig, ETH_ALEN) != 0)
		return NL_OK;

	memcpy(&opts->tq, tq, sizeof(uint8_t));
	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int find_tq(const char *mesh_iface, const struct ether_addr *mac,
		uint8_t *tq_out)
{
	struct find_tq_netlink_opts opts = {
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	memcpy(&opts.mac, mac, ETH_ALEN);

	ret = batadv_nl_query_common(mesh_iface,
					BATADV_CMD_GET_ORIGINATORS,
					find_tq_netlink_cb, NLM_F_DUMP,
					&opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	memcpy(tq_out, &opts.tq, sizeof(uint8_t));

	return 0;
}

static void parse_cmdline(int argc, char *argv[]) {
	int c;
	unsigned long int threshold;
	char *endptr;
	while ((c = getopt(argc, argv, "c:hi:m:t:")) != -1) {
		switch (c) {
			case 'i':
				G.iface = optarg;
				break;
			case 'm':
				G.mesh_iface = optarg;
				break;
			case 'c':
				G.chain = optarg;
				break;
			case 't':
				threshold = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0')
					exit_errmsg("Threshold must be a number: %s", optarg);
				G.hysteresis_thresh = (uint16_t) threshold;
				break;
			case 'h':
				usage(NULL);
				break;
			default:
				usage("");
				break;
		}
	}
}

static void handle_ra(int sock) {
	struct sockaddr_ll src;
	unsigned int addr_size = sizeof(src);
	size_t len;
	struct {
		struct ip6_hdr ip6;
		struct nd_router_advert ra;
	} pkt;

	len = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&src, &addr_size);

	// BPF already checked that this is an ICMPv6 RA of a default router
	CHECK(len >= sizeof(pkt));
	CHECK(ntohs(pkt.ip6.ip6_plen) + sizeof(struct ip6_hdr) >= sizeof(pkt));

	DEBUG_MSG("received valid RA from %s", ether_ntoa_long((struct ether_addr *)src.sll_addr));

	// update list of known routers
	struct router *router;
	foreach(router, G.routers) {
		if (!memcmp((struct ether_addr *)&router->src, src.sll_addr, ETH_ALEN)) {
			break;
		}
	}
	if (!router) {
		router = malloc(sizeof(struct router));
		memcpy(&router->src, src.sll_addr, ETH_ALEN);
		router->next = G.routers;
		G.routers = router;
	}
	router->eol = time(NULL) + pkt.ra.nd_ra_router_lifetime;

check_failed:
	return;
}

static void expire_routers() {
	struct router **prev_ptr = &G.routers;
	struct router *router;
	time_t now = time(NULL);

	foreach(router, G.routers) {
		if (router->eol < now) {
			DEBUG_MSG("router %s expired", ether_ntoa_long(&router->src));
			*prev_ptr = router->next;
			if (G.best_router == router)
				G.best_router = NULL;
			free(router);
		} else {
			prev_ptr = &router->next;
		}
	}
}

static void update_tqs() {
	struct router *router;
	bool update_originators = false;
	char mac[F_MAC_LEN + 1];
	struct ether_addr *unspec = malloc(ETH_ALEN); memset(unspec,0,ETH_ALEN);

	// reset TQs
	foreach(router, G.routers) {
		router->tq = 0;
		snprintf(mac, sizeof(mac), "%s", ether_ntoa_long(&router->src));
		DEBUG_MSG("current originator for %s is %s",
			mac, ether_ntoa_long(&router->originator));
		if (!memcmp(&router->originator, unspec, ETH_ALEN))
			update_originators = true;
	}

	free(unspec);

	if (update_originators) {
		// translate all router's MAC addresses to originators
		foreach(router, G.routers) {
			DEBUG_MSG("lookup originator for %s",
				ether_ntoa_long(&router->src));
			if (!find_originator(G.mesh_iface, &router->src, &router->originator)) {
				snprintf(mac, sizeof(mac), "%s", ether_ntoa_long(&router->src));
				DEBUG_MSG("found originator %s for %s",
					ether_ntoa_long(&router->originator), mac);
			}
		}
	}

	// Reset max_tq
	G.max_tq = 0;

	// look up TQs
	foreach(router, G.routers) {
		if (!find_tq(G.mesh_iface, &router->originator, &router->tq)) {
			DEBUG_MSG("found TQ=%d for %s",
				router->tq, ether_ntoa_long(&router->src));
			if (router->tq > G.max_tq) {
				G.max_tq = router->tq;
			}
		}
	}

	foreach(router, G.routers) {
		if (router->tq == 0) {
			fprintf(stderr, "didn't find TQ for %s\n", ether_ntoa_long(&router->src));
		}
	}

}

static int fork_execvp_timeout(struct timespec *timeout, const char *file, const char *const argv[]) {
	int ret;
	pid_t child;
	siginfo_t info;
	sigset_t signals, oldsignals;
	sigemptyset(&signals);
	sigaddset(&signals, SIGCHLD);

	sigprocmask(SIG_BLOCK, &signals, &oldsignals);
	child = fork();
	if (child == 0) {
		sigprocmask(SIG_SETMASK, &oldsignals, NULL);
		// casting discards const, but should be safe
		// (see http://stackoverflow.com/q/36925388)
		execvp(file, (char**) argv);
		error_message(1, errno, "can't execvp(\"%s\", ...)", file);
	}

	ret = sigtimedwait(&signals, &info, timeout);
	sigprocmask(SIG_SETMASK, &oldsignals, NULL);

	if (ret == SIGCHLD) {
		if (info.si_pid != child) {
			cleanup();
			error_message(1, 0,
				"BUG: We received a SIGCHLD from a child we didn't spawn (expected PID %d, got %d)",
				child, info.si_pid);
		}

		waitpid(child, NULL, 0);

		return info.si_status;
	}

	if (ret < 0 && errno == EAGAIN)
		error_message(0, 0, "warning: child %d took too long, killing", child);
	else if (ret < 0)
		warn_errno("sigtimedwait failed, killing child");
	else
		error_message(1, 0,
				"BUG: sigtimedwait() return some other signal than SIGCHLD: %d",
				ret);

	kill(child, SIGKILL);
	kill(child, SIGCONT);
	waitpid(child, NULL, 0);
	return -1;
}

static void update_ebtables() {
	struct timespec timeout = {
		.tv_nsec = EBTABLES_TIMEOUT,
	};
	char mac[F_MAC_LEN + 1];
	struct router *router;

	if (G.best_router && G.best_router->tq >= G.max_tq - G.hysteresis_thresh) {
		DEBUG_MSG("%s is still good enough with TQ=%d (max_tq=%d), not executing ebtables",
			ether_ntoa_long(&G.best_router->src),
			G.best_router->tq,
			G.max_tq);
		return;
	}

	foreach(router, G.routers) {
		if (router->tq == G.max_tq) {
			snprintf(mac, sizeof(mac), "%s", ether_ntoa_long(&router->src));
			break;
		}
	}
	if (G.best_router)
		fprintf(stderr, "Switching from %s (TQ=%d) to %s (TQ=%d)\n",
			ether_ntoa_long(&G.best_router->src),
			G.best_router->tq,
			mac,
			G.max_tq);
	else
		fprintf(stderr, "Switching to %s (TQ=%d)\n",
			mac,
			G.max_tq);
	G.best_router = router;

	if (fork_execvp_timeout(&timeout, "ebtables", (const char *[])
			{ "ebtables", "-F", G.chain, NULL }))
		error_message(0, 0, "warning: flushing ebtables chain %s failed, not adding a new rule", G.chain);
	else if (fork_execvp_timeout(&timeout, "ebtables", (const char *[])
			{ "ebtables", "-A", G.chain, "-s", mac, "-j", "ACCEPT", NULL }))
		error_message(0, 0, "warning: adding new rule to ebtables chain %s failed", G.chain);
}

int main(int argc, char *argv[]) {
	unsigned int ifindex;
	int retval;
	fd_set rfds;
	struct timeval tv;
	time_t last_update = time(NULL);

	parse_cmdline(argc, argv);

	ifindex = if_nametoindex(G.iface);
	if (ifindex == 0)
		exit_errmsg("Unknown interface: %s", G.iface);
	G.sock = init_packet_socket(ifindex);

	if (G.chain == NULL)
		usage("No chain set!");

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(G.sock, &rfds);

		tv.tv_sec = MAX_INTERVAL;
		tv.tv_usec = 0;
		retval = select(G.sock + 1, &rfds, NULL, NULL, &tv);

		if (retval < 0)
			exit_errno("select() failed");
		else if (retval) {
			if (FD_ISSET(G.sock, &rfds)) {
				handle_ra(G.sock);
			}
		}
		else {
			// sometimes nothing is received via the socket
			// re-initialize socket if this is the case
			DEBUG_MSG("select() timeout expired; re-init packet socket");
			ifindex = if_nametoindex(G.iface);
			G.sock = init_packet_socket(ifindex);
		}

		if (G.routers != NULL && last_update <= time(NULL) - MIN_INTERVAL) {
			expire_routers();

			// all routers could have expired, check again
			if (G.routers != NULL) {
				update_tqs();
				update_ebtables();
				last_update = time(NULL);
			}
		}
	}

	cleanup();
	return 0;
}
