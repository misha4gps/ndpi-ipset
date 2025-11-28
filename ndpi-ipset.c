#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ndpi_api.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

#include <libipset/session.h>
#include <libipset/types.h>
#include <libipset/ipset.h>

#include "zbxalgo.h"


#define MAX_FLOWS 2000
#define IDLE_TIMEOUT (60*5) // 5 minutes
#define IDLE_IPSET_TIMEOUT (60*60) // 1 hour
#define BUFFER_SIZE 65536
#ifndef DEBUG
#  define DEBUG 1
#endif

const char* get_timestamp_with_diff();
#if DEBUG
// #define DBG_PRINTF(fmt, ...) printf("[DEBUG %s] " fmt, get_timestamp_with_diff(), ##__VA_ARGS__)
void dbg_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define DBG_PRINTF(fmt, ...) dbg_printf(fmt,  ##__VA_ARGS__)
#else
#define DBG_PRINTF(fmt, ...) do {} while(0)
#endif

ZBX_VECTOR_DECL(uint16, zbx_uint16_t)
ZBX_VECTOR_IMPL(uint16, zbx_uint16_t)

typedef struct ip_mask {
    uint32_t network;
    uint32_t mask;
} ip_mask_t;

ZBX_VECTOR_DECL(ip_mask, ip_mask_t)
ZBX_VECTOR_IMPL(ip_mask, ip_mask_t)

typedef struct ip_ref {
    uint32_t ip;
    uint16_t count;
} ip_ref_t;

ZBX_VECTOR_DECL(ip_ref, ip_ref_t)
ZBX_VECTOR_IMPL(ip_ref, ip_ref_t)

typedef struct proto_str {
    char name[128];
} proto_str_t;
ZBX_VECTOR_DECL(proto_str, proto_str_t)
ZBX_VECTOR_IMPL(proto_str, proto_str_t)

struct flow_info {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    struct ndpi_flow_struct *ndpi_flow;
    ndpi_protocol detected_protocol;
    time_t last_seen;
    time_t first_seen;
    int is_detected;
    uint8_t detection_completed;
    uint32_t packets_processed;
};

static int raw_socket = -1;
static struct ndpi_detection_module_struct *ndpi_ctx = NULL;
static struct flow_info flows[MAX_FLOWS];
static int flow_count = 0;
static volatile int running = 1;
static uint64_t total_packets = 0;
zbx_vector_uint16_t detected_protocols;
zbx_vector_proto_str_t detected_apps;
static const char *add_line = NULL;
static const char *del_line = NULL;
static const char *int_net_line = NULL;
zbx_vector_ip_mask_t internal_nets;
zbx_vector_ip_ref_t ipset_ips;
static struct ipset *ips = NULL;
static struct ipset_session *ips_session = NULL;
static const char *ipset_name = NULL;
static uint32_t ipset_timeout = 0;
static const char *diag_ip = NULL;

#define ZBX_WHITESPACE			" \t\r\n"
#define SKIP_WHITESPACE(src)	\
	while ('\0' != *(src) && NULL != strchr(ZBX_WHITESPACE, *(src))) (src)++
 
int init_raw_socket(const char *interface);
int init_ndpi();
void cleanup();
void signal_handler(int sig);
struct flow_info* get_flow_info(uint32_t src_ip, uint32_t dst_ip, 
                               uint16_t src_port, uint16_t dst_port, uint8_t protocol);
int process_packet(unsigned char *buffer, int length);
int parse_ethernet_frame(unsigned char *buffer, int length, 
                        struct iphdr **ip_header, void **l4_header, int *l4_len);
void cleanup_old_flows();
void mark_traffic_exec(const struct flow_info *flow, const char *exec_line);
void to_lower(char *dest, const char *src);
int ipset_add_entry(const struct in_addr *ip);
int ipset_del_entry(const struct in_addr *ip);



int detect_proto(const struct flow_info *flow, int *protocol_id, const char *app) {
    ndpi_protocol protocol = flow->detected_protocol;
    char app_lower[128] = {0};
    to_lower(app_lower, app);

    if (
        (*protocol_id = zbx_vector_uint16_bsearch(
            &detected_protocols, protocol.app_protocol, zbx_default_uint16_compare_func)
        ) != FAIL || 
        (*protocol_id = zbx_vector_uint16_bsearch(
            &detected_protocols, protocol.master_protocol, zbx_default_uint16_compare_func)
        ) != FAIL
    ) {
        for (int i = 0; i < internal_nets.values_num; i++) {
            if ((flow->dst_ip & internal_nets.values[i].mask) == internal_nets.values[i].network) {
                DBG_PRINTF("[p]:Internal network match: %s/%d\n", 
                    inet_ntoa(*(struct in_addr*)&internal_nets.values[i].network), 
                    __builtin_popcount(internal_nets.values[i].mask));
                return 0;
            }
        }

        return 1;
    }

    for (int i = 0; i < detected_apps.values_num; i++) {
        if (strstr(app_lower, detected_apps.values[i].name) != NULL) {
            for (int i = 0; i < internal_nets.values_num; i++) {
                if ((flow->dst_ip & internal_nets.values[i].mask) == internal_nets.values[i].network) {
                    DBG_PRINTF("[a]:Internal network match: %s/%d\n", 
                        inet_ntoa(*(struct in_addr*)&internal_nets.values[i].network), 
                        __builtin_popcount(internal_nets.values[i].mask));
                    return 0;
                }
            }
            *protocol_id = i;
            return 1;
        }
    }

    return 0;
}

void to_lower(char *dest, const char *src) {
    while (*src) {
        *dest++ = tolower((unsigned char)*src++);
    }
    *dest = '\0';
}

#if DEBUG
const char* get_timestamp_with_diff() {
    static struct timeval prev = {0, 0};
    static char buffer[64];

    struct timeval now;
    struct tm *tm_info;
    long diff_ms;

    gettimeofday(&now, NULL);
    tm_info = localtime(&now.tv_sec);

    if (prev.tv_sec == 0 && prev.tv_usec == 0) {
        diff_ms = 0;
    } else {
        diff_ms = (now.tv_sec - prev.tv_sec) * 1000L +
                  (now.tv_usec - prev.tv_usec) / 1000L;
    }

    snprintf(buffer, sizeof(buffer), "%02d_%02d.%02d.%02d-%03ld/%ld",
             tm_info->tm_mday,
             tm_info->tm_hour,
             tm_info->tm_min,
             tm_info->tm_sec,
             now.tv_usec / 1000,
             diff_ms);

    prev = now;

    return buffer;
}

void dbg_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[DEBUG %s] ", get_timestamp_with_diff());
    vfprintf(stderr, fmt, args);
    va_end(args);
}
#endif

void free_flow(struct flow_info *flow) {
    if (!flow) return;

    if (flow->ndpi_flow) {
        ndpi_free_flow(flow->ndpi_flow);
    }

    memset(flow, 0, sizeof(struct flow_info));
}

int init_raw_socket(const char *interface) {
    struct sockaddr_ll addr;
    struct ifreq ifr;
    int sock;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    int sock_buf_size = 8 * 1024 * 1024; // 8MB
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size)) < 0) {
        perror("setsockopt SO_RCVBUF");
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(sock);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    printf("Raw socket created and bound to interface %s\n", interface);
    return sock;
}

int init_ndpi() {
    NDPI_PROTOCOL_BITMASK all;

    ndpi_ctx = ndpi_init_detection_module(ndpi_no_prefs);
    if (ndpi_ctx == NULL) {
        fprintf(stderr, "Error initializing nDPI\n");
        return -1;
    }

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_ctx, &all);

    ndpi_finalize_initialization(ndpi_ctx);

    printf("nDPI initialized successfully\n");
    return 0;
}

void cleanup_old_flows() {
    time_t now = time(NULL);
    int i = 0;

    while (i < flow_count) {
        if (
            (!flows[i].is_detected && now - flows[i].last_seen > IDLE_TIMEOUT) ||
            ( flows[i].is_detected && now - flows[i].last_seen > ipset_timeout && 0 != ipset_timeout)
        ) {
            if (flows[i].is_detected && del_line)
            {
                int idx = zbx_vector_ip_ref_bsearch(&ipset_ips, (ip_ref_t){flows[i].dst_ip, 0}, zbx_default_uint32_compare_func);
                if (idx != FAIL) {
                    if (ipset_ips.values[idx].count == 1) {
                        mark_traffic_exec(&flows[i], del_line);
                        zbx_vector_ip_ref_remove(&ipset_ips, idx);
                        ipset_del_entry((struct in_addr*)&flows[i].dst_ip);
                    } else {
                        ipset_ips.values[idx].count--;
                    }
                }
            }
            free_flow(&flows[i]);

            if (i < flow_count - 1) {
                memcpy(&flows[i], &flows[flow_count - 1], sizeof(struct flow_info));
                memset(&flows[flow_count - 1], 0, sizeof(struct flow_info));
            }
            flow_count--;
        } else {
            i++;
        }
    }
}

struct flow_info* get_flow_info(uint32_t src_ip, uint32_t dst_ip, 
                               uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    time_t now = time(NULL);

    for (int i = 0; i < flow_count; i++) {
        if (
                (
                    flows[i].src_ip == src_ip && 
                    flows[i].dst_ip == dst_ip &&
                    flows[i].src_port == src_port && 
                    flows[i].dst_port == dst_port &&
                    flows[i].protocol == protocol
                ) || (
                    flows[i].src_ip == dst_ip && 
                    flows[i].dst_ip == src_ip &&
                    flows[i].src_port == dst_port && 
                    flows[i].dst_port == src_port &&
                    flows[i].protocol == protocol)
                )
        {
            flows[i].last_seen = now;
            return &flows[i];
        }
    }

    if (total_packets % 1000 == 0) {
        cleanup_old_flows();
    }

    if (flow_count < MAX_FLOWS) {
        struct flow_info *flow = &flows[flow_count];
        memset(flow, 0, sizeof(struct flow_info));

        flow->src_ip = src_ip;
        flow->dst_ip = dst_ip;
        flow->src_port = src_port;
        flow->dst_port = dst_port;
        flow->protocol = protocol;
        flow->first_seen = flow->last_seen = now;

        size_t flow_size = ndpi_detection_get_sizeof_ndpi_flow_struct();
        flow->ndpi_flow = ndpi_flow_malloc(flow_size);
        if (!flow->ndpi_flow) {
            fprintf(stderr, "Error allocating nDPI flow structure\n");
            return NULL;
        }
        memset(flow->ndpi_flow, 0, flow_size);

        flow_count++;
        return flow;
    }

    return NULL;
}

int parse_ethernet_frame(unsigned char *buffer, int length, 
        struct iphdr **ip_header, void **l4_header, int *l4_len) {
    struct ethhdr *eth_header;
    struct iphdr *ip;

    if (length < (int)sizeof(struct ethhdr)) return -1;
    
    eth_header = (struct ethhdr*)buffer;
    if (ntohs(eth_header->h_proto) != ETH_P_IP) return -1;

    buffer += sizeof(struct ethhdr);
    length -= sizeof(struct ethhdr);
    
    if (length < (int)sizeof(struct iphdr)) return -1;

    ip = (struct iphdr*)buffer;
    if (ip->version != 4) return -1;

    int ip_header_len = ip->ihl * 4;
    if (length < ip_header_len || ip_header_len < (int)sizeof(struct iphdr)) return -1;

    *ip_header = ip;
    *l4_header = buffer + ip_header_len;
    *l4_len = length - ip_header_len;

    return 0;
}

/*** libipset *****************************/
static const char *ipset_session_strerror(struct ipset_session *session)
{
    const char *msg = NULL;
    static char buf[256];

#if defined(HAVE_IPSET_SESSION_ERROR) || defined(IPSET_SESSION_ERR_H)
    /* libipset (>=7.10) */
    if (ipset_session_error(session))
        msg = ipset_session_error(session);
#else
    msg = ipset_session_report_msg(session);
#endif

    int len = snprintf(buf, sizeof(buf), "%s", msg ? msg : strerror(errno));
    if ('\n' == buf[len - 1])
        buf[len - 1] = '\0';
    ipset_session_report_reset(session);
    return buf;
}

uint8_t ipset_ip_exists(const struct in_addr *ip, const char *fn)
{
    int ret = -1;
    uint8_t family = AF_INET;

    if (!ips_session) {
        return -1;
    }

    if (!ipset_name || !ip) {
        fprintf(stderr, "ipset_ip_exists: invalid arguments\n");
        return -1;
    }

    ipset_session_data_set(ips_session, IPSET_SETNAME, ipset_name);
    ipset_session_data_set(ips_session, IPSET_OPT_FAMILY, &family);
    ipset_session_data_set(ips_session, IPSET_OPT_IP, ip);

    if (NULL == ipset_type_get(ips_session, IPSET_CMD_TEST)) {
        fprintf(stderr, "ipset_ip_exists: failed to get set type for set %s\n", ipset_name);
        return -1;
    }
    ret = ipset_cmd(ips_session, IPSET_CMD_TEST, 0);
    DBG_PRINTF("[%s] ipset_ip_exists(%s): %s => %s [error:%s]\n", fn, ipset_name, 
        inet_ntoa(*ip), ret == 0 ? "exists" : "not exists", ipset_session_strerror(ips_session));
    return ret == 0 ? 1 : 0;
}

int ipset_del_entry(const struct in_addr *ip)
{
    int ret = -1;
    uint8_t family = AF_INET;

    if (!ips_session) {
        return -1;
    }

    if (!ipset_name || !ip) {
        fprintf(stderr, "ipset_del_entry: invalid arguments\n");
        return -1;
    }

    if (ipset_ip_exists(ip, __func__) == 0) {
        return 0;
    }

    ipset_session_data_set(ips_session, IPSET_SETNAME, ipset_name);
    ipset_session_data_set(ips_session, IPSET_OPT_FAMILY, &family);
    ipset_session_data_set(ips_session, IPSET_OPT_IP, ip);

    if (NULL == ipset_type_get(ips_session, IPSET_CMD_DEL)) {
        fprintf(stderr, "ipset_del_entry: failed to get set type for set %s\n", ipset_name);
        return -1;
    }

    if (0 != (ret = ipset_cmd(ips_session, IPSET_CMD_DEL, 0))) {
        fprintf(stderr, "ipset del failed(%s): %s\n", inet_ntoa(*ip), ipset_session_strerror(ips_session));
    }

    if (!ret)
        DBG_PRINTF("ipset_del_entry(%s): %s\n", ipset_name, inet_ntoa(*ip));

    return ret;
}

int ipset_add_entry(const struct in_addr *ip)
{
    int ret = -1;
    uint8_t family = AF_INET;

    if (!ips_session) {
        return -1;
    }

    if (!ipset_name || !ip) {
        fprintf(stderr, "ipset_add_entry: invalid arguments\n");
        return -1;
    }
    
    if (ipset_del_entry(ip) != 0) { // update timeout by re-adding
        return -1;
    }

    ipset_session_data_set(ips_session, IPSET_SETNAME, ipset_name);
    ipset_session_data_set(ips_session, IPSET_OPT_TYPENAME, "hash:ip");
    ipset_session_data_set(ips_session, IPSET_OPT_FAMILY, &family);
    ipset_session_data_set(ips_session, IPSET_OPT_IP, ip);

    if (ipset_timeout > 0)
        ipset_session_data_set(ips_session, IPSET_OPT_TIMEOUT, &ipset_timeout);

    if (NULL == ipset_type_get(ips_session, IPSET_CMD_ADD)) {
        fprintf(stderr, "ipset_add_entry: failed to get set type for set %s\n", ipset_name);
        return -1;
    }

    if ((ret = ipset_cmd(ips_session, IPSET_CMD_ADD, 0)) != 0) {
        fprintf(stderr, "ipset(%s) add failed(%s raw: 0x%08x): %s\n",
            ipset_name, inet_ntoa(*ip), ntohl(ip->s_addr), ipset_session_strerror(ips_session));
    }

    if (!ret)
        DBG_PRINTF("ipset_add_entry(%s): %s\n", ipset_name, inet_ntoa(*ip));

    return ret;
}

int ipset_set_exists(const char * setname)
{
    if (!ips_session || !setname) {
        fprintf(stderr, "ipset_set_exists: invalid args\n");
        return -1;
    }

    ipset_load_types();
    ipset_session_data_set(ips_session, IPSET_SETNAME, setname);
    
    if (NULL != ipset_type_get(ips_session, IPSET_CMD_TEST)) {
        DBG_PRINTF("ipset '%s' exists\n", setname);
        return 1;
    } else {
        const char *errmsg = ipset_session_strerror(ips_session);
        if (errmsg && strstr(errmsg, "does not exist")) {
            DBG_PRINTF("ipset '%s' does not exist\n", setname);
            return 0;
        } else {
            fprintf(stderr, "ipset_set_exists: list failed: %s\n",
                    errmsg ? errmsg : strerror(errno));
            return -1;
        }
    }
}

int ipset_add_ipset(const char * setname) {
    if (!ips_session || !setname) {
        fprintf(stderr, "ipset_add_ipset: invalid args\n");
        return -1;
    }

    ipset_session_data_set(ips_session, IPSET_SETNAME, setname);
    ipset_session_data_set(ips_session, IPSET_OPT_TYPENAME, "hash:ip");
    uint8_t family = AF_INET;
    ipset_session_data_set(ips_session, IPSET_OPT_FAMILY, &family);
    uint32_t z = 0;
    ipset_session_data_set(ips_session, IPSET_OPT_TIMEOUT, &z);

    if (NULL == ipset_type_get(ips_session, IPSET_CMD_CREATE)) {
        fprintf(stderr, "ipset_add_entry: failed to get set type for set %s\n", ipset_name);
        return -1;
    }
    int ret = ipset_cmd(ips_session, IPSET_CMD_CREATE, 0);
    if (ret != 0) {
        fprintf(stderr, "ipset_create(%s) failed: %s\n", setname,
                ipset_session_strerror(ips_session));
        return -1;
    }

    DBG_PRINTF("ipset '%s' created successfully\n", setname);
    return 0;
}

/*** exec cli *****************************/
char **split_cmd_to_argv(const char *cmd) {
    if (!cmd) return NULL;

    size_t argc = 0;
    size_t argv_size = 8;
    char **argv = malloc(argv_size * sizeof(char *));
    if (!argv) return NULL;

    const char *p = cmd;
    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (argc + 1 >= argv_size) {
            argv_size *= 2;
            argv = realloc(argv, argv_size * sizeof(char *));
            if (!argv) return NULL;
        }

        char *arg = malloc(strlen(p) + 1);
        if (!arg) return NULL;
        char *dst = arg;
        int in_quotes = 0;
        char quote_char = 0;

        while (*p) {
            if (in_quotes) {
                if (*p == '\\' && p[1]) {
                    *dst++ = p[1];
                    p += 2;
                } else if (*p == quote_char) {
                    in_quotes = 0;
                    p++;
                } else {
                    *dst++ = *p++;
                }
            } else {
                if (isspace((unsigned char)*p)) {
                    p++;
                    break;
                } else if (*p == '\'' || *p == '"') {
                    in_quotes = 1;
                    quote_char = *p++;
                } else if (*p == '\\' && p[1]) {
                    *dst++ = p[1];
                    p += 2;
                } else {
                    *dst++ = *p++;
                }
            }
        }
        *dst = '\0';
        argv[argc++] = arg;
    }

    argv[argc] = NULL;
    return argv;
}

void free_argv(char **argv) {
    if (!argv) return;
    for (size_t i = 0; argv[i]; i++)
        free(argv[i]);
    free(argv);
}

int run_cmd_argv(char *const argv[]) {
    pid_t pid;
    int status;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;

    posix_spawnattr_init(&attr);
    posix_spawn_file_actions_init(&actions);

    int rc = posix_spawn(&pid, argv[0], &actions, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);

    if (rc != 0) {
        errno = rc;
        perror("posix_spawn failed");
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid failed");
        return -1;
    }
    return status;
}

void mark_traffic_exec(const struct flow_info *flow, const char *exec_line) {

    if (!exec_line || *exec_line == '\0')
        return;

    char cmd[1024];
    struct in_addr src_addr, dst_addr;

    src_addr.s_addr = flow->src_ip;
    dst_addr.s_addr = flow->dst_ip;

    char sip_str[INET_ADDRSTRLEN], dip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, sip_str, sizeof(sip_str));
    inet_ntop(AF_INET, &dst_addr, dip_str, sizeof(dip_str));

    snprintf(cmd, sizeof(cmd), exec_line,
        dip_str, flow->dst_port,
        sip_str, flow->src_port,
        flow->protocol == IPPROTO_TCP ? "tcp" : "udp"
    );

    DBG_PRINTF("Executing command: %s\n", cmd);
    char **argv = split_cmd_to_argv(cmd);
    int ret = run_cmd_argv(argv);    
    if (ret != 0) {
        DBG_PRINTF("Command execution failed with code: %d\n", ret);
    }
    free_argv(argv);
}

// === Packet processing ===================
int process_packet(unsigned char *buffer, int length) {
    struct iphdr *ip_header;
    void *l4_header;
    int l4_len;
    struct flow_info *flow;
    ndpi_protocol protocol;

    total_packets++;
    
    if (parse_ethernet_frame(buffer, length, &ip_header, &l4_header, &l4_len) < 0) {
        return -1;
    }

    uint16_t src_port = 0, dst_port = 0;

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)l4_header;
        if (l4_len < (int)sizeof(struct tcphdr)) return -1;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr*)l4_header;
        if (l4_len < (int)sizeof(struct udphdr)) return -1;
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    } else {
        return -1;
    }

    flow = get_flow_info(ip_header->saddr, ip_header->daddr, 
                        src_port, dst_port, ip_header->protocol);

    if (!flow) return -1;

    flow->packets_processed++;

    if (flow->detection_completed) {
        return 0;
    }

    if (flow->packets_processed > 20) {
        flow->detection_completed = 1;
        return 0;
    }

    protocol = ndpi_detection_process_packet(
        ndpi_ctx, flow->ndpi_flow,
        (uint8_t*)(buffer + sizeof(struct ethhdr)),
        length - sizeof(struct ethhdr),
        time(NULL)
    );

    flow->detected_protocol = protocol;

    if (protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN || 
        protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN) {

        flow->detection_completed = 1;

        char protocol_buf[128];
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = flow->src_ip;
        dst_addr.s_addr = flow->dst_ip;

        const char *app_proto = ndpi_get_proto_name(ndpi_ctx, protocol.app_protocol);
        const char *master_proto = ndpi_get_proto_name(ndpi_ctx, protocol.master_protocol);

        if (protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN && 
            protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            snprintf(protocol_buf, sizeof(protocol_buf), "%s.%s", 
                    master_proto ? master_proto : "Unknown",
                    app_proto ? app_proto : "Unknown");
        } else if (protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            snprintf(protocol_buf, sizeof(protocol_buf), "%s", 
                    app_proto ? app_proto : "Unknown");
        } else if (protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            snprintf(protocol_buf, sizeof(protocol_buf), "%s", 
                    master_proto ? master_proto : "Unknown");
        } else {
            strcpy(protocol_buf, "Unknown");
        }

        char sip_str[INET_ADDRSTRLEN], dip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, sip_str, sizeof(sip_str));
        inet_ntop(AF_INET, &dst_addr, dip_str, sizeof(dip_str));

        int protocol_id = -2;
        if (detect_proto(flow, &protocol_id , protocol_buf)) {

            DBG_PRINTF("Detected protocol: [%d]%s for flow %s:%d -> %s:%d (after %d packets)\n",
                    protocol_id, protocol_buf,
                    sip_str, flow->src_port,
                    dip_str, flow->dst_port,
                    flow->packets_processed);

            int idx = zbx_vector_ip_ref_bsearch(&ipset_ips, (ip_ref_t){flow->dst_ip, 0}, zbx_default_uint32_compare_func);
            if (idx == FAIL)
            {
                zbx_vector_ip_ref_append(&ipset_ips, (ip_ref_t){flow->dst_ip, 1});
                zbx_vector_ip_ref_sort(&ipset_ips, zbx_default_uint32_compare_func);
            }
            else
                ipset_ips.values[idx].count++;

            flow->is_detected = 1;
            mark_traffic_exec(flow, add_line);
            ipset_add_entry(&dst_addr);

        } else if (diag_ip != NULL && (strstr(sip_str, diag_ip) != NULL || strstr(dip_str, diag_ip) != NULL)) {
            DBG_PRINTF("Ignored protocol: %s for flow %s:%d -> %s:%d (after %d packets)\n",
                    protocol_buf,
                    sip_str, flow->src_port,
                    dip_str, flow->dst_port,
                    flow->packets_processed);
        }
    }

    return 0;
}

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
}

static void print_usage(const char *progname) {
    printf("Usage: %s [interface] [proto_file] [add_line] [del_line] [int_nets] [diag_ip] [ipset_name] [ipset_timeout]\n", progname);
    printf("  1) interface   - network interface to capture (default: br0). Use '-' to skip.\n");
    printf("  2) proto_file  - file with protocol IDs/names or '-' to use built-in defaults.\n");
    printf("  3) add_line    - command template to run on detection (use '-' to disable).\n");
    printf("  4) del_line    - command template to run on flow timeout (use '-' to disable).\n");
    printf("  5) int_nets    - comma-separated internal networks (e.g. 192.168.0.0/24) or '-' to disable.\n");
    printf("  6) diag_ip     - diagnostic IP substring to always log (default: %s)\n", diag_ip);
    printf("  7) ipset_name  - name of ipset to manage or '-' to disable.\n");
    printf("  8) ipset_timeout - timeout for ipset entries in seconds (default: 3600).\n");
    printf("\nExamples:\n");
    printf("  %s eno1 proto.list \"ipset add vpn-riga %%s\" \"ipset del vpn-riga %%s\" 192.168.0.0/24 192.168.0.53 vpn-riga 3600\n", progname);
}

void cleanup() {
    printf("Cleaning up...\n");

    if (raw_socket >= 0) {
        close(raw_socket);
        raw_socket = -1;
    }

    for (int i = 0; i < flow_count; i++) {
        if (flows[i].is_detected && del_line)
        {
            int idx = zbx_vector_ip_ref_bsearch(&ipset_ips, (ip_ref_t){flows[i].dst_ip, 0}, zbx_default_uint32_compare_func);
            if (idx != FAIL) {
                if (ipset_ips.values[idx].count == 1) {
                    mark_traffic_exec(&flows[i], del_line);
                    zbx_vector_ip_ref_remove(&ipset_ips, idx);
                    ipset_del_entry((struct in_addr*)&flows[i].dst_ip);
                } else {
                    ipset_ips.values[idx].count--;
                }
            }
        }

        free_flow(&flows[i]);
    }
    flow_count = 0;

        if (ndpi_ctx) {
            ndpi_exit_detection_module(ndpi_ctx);
            ndpi_ctx = NULL;
    #if defined(GCRYCTL_TERM_SECMEM)
            gcry_control(GCRYCTL_TERM_SECMEM);
    #elif defined(GCRYCTL_RELEASE_SECMEM)
            gcry_control(GCRYCTL_RELEASE_SECMEM);
    #endif
        }

    zbx_vector_uint16_destroy(&detected_protocols);
    zbx_vector_proto_str_destroy(&detected_apps);
    zbx_vector_ip_mask_destroy(&internal_nets);
    zbx_vector_ip_ref_destroy(&ipset_ips);

    if (ips) {
        ipset_fini(ips);
    }

    printf("Cleanup completed\n");
}

// === Config parsing =====================
void read_line_numbers(const char *filename) {

    if (!filename || !*filename) {
        perror("error open file");
        exit(1);
    }

    char full_path[1024];
    *full_path = '\0';

    if (*filename == '-') {
        char exe_path[1024];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len == -1) {
            perror("Error of path getting");
            exit(1);
        }
        exe_path[len] = '\0';

        char exe_dir[1024];
        strncpy(exe_dir, exe_path, sizeof(exe_dir));
        exe_dir[sizeof(exe_dir) - 1] = '\0';

        char *dir = dirname(exe_dir);
        snprintf(full_path, sizeof(full_path), "%s/proto.list", dir);
    }

    FILE *file = NULL;

    if (*filename == '-' && (*full_path == '\0' || (file = fopen(full_path, "r")) == NULL)) {
        zbx_vector_uint16_append(&detected_protocols, NDPI_PROTOCOL_WHATSAPP_CALL);
        zbx_vector_uint16_append(&detected_protocols, NDPI_PROTOCOL_WHATSAPP);
        zbx_vector_uint16_append(&detected_protocols, NDPI_PROTOCOL_WHATSAPP_FILES);
        zbx_vector_proto_str_append(&detected_apps, (proto_str_t){"whatsapp"});
        DBG_PRINTF("Using built-in protocol list\n");
        return;
    } else if (*filename != '-' && (file = fopen(filename, "r")) == NULL){
        fprintf(stderr, "error open file: %s\n", filename);
        exit(1);
    } else if (!file) {
        fprintf(stderr, "Error open file: %s\n", filename);
        exit(1);
    }

    char line[1024];
    int line_number = 1;

    while (fgets(line, sizeof(line), file)) {
        char *ptr = line;

        SKIP_WHITESPACE(ptr);

        if (*ptr == '#' || *ptr == '\0') {
            line_number++;
            continue;
        }
        uint16_t number = 0;
        int matched = sscanf(ptr, "%hu", &number);

        if (matched == 1) {
            zbx_vector_uint16_append(&detected_protocols, number);
            DBG_PRINTF("String %d: number — %d\n", line_number, number);
        } else {
            char *endptr = ptr;
            while (*endptr && !isspace((unsigned char)*endptr)) endptr++;
            size_t len = endptr - ptr;
        
            if (len < (int)sizeof(((proto_str_t *)0)->name)) {
                proto_str_t ps;
                strncpy(ps.name, ptr, len);
                ps.name[len] = '\0';
                to_lower(ps.name, ps.name);
                zbx_vector_proto_str_append(&detected_apps, ps);
                DBG_PRINTF("String %d: app — %s\n", line_number, ps.name);
            } else {
                fprintf(stderr, "Line %d: app name too long, skipping\n", line_number);
            }
        }

        line_number++;
    }

    DBG_PRINTF("added %d numbers from file %s\n", detected_protocols.values_num, filename);

    fclose(file);
}

void ip_mask_parse_line(const char *line, zbx_vector_ip_mask_t *masks) {
    if (!line || !*line) return;

    char *line_copy = strdup(line);
    if (!line_copy) return;

    char *token = strtok(line_copy, ",");
    while (token) {
        SKIP_WHITESPACE(token);

        int mask_len = 32;
        char *mask_str = NULL;
        char *ip_str = token;
        char *slash = strchr(token, '/');
        if (slash) {
            *slash = '\0';
            mask_str = slash + 1;
            mask_len = atoi(mask_str);
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) == 1) {
            if (mask_len >= 0 && mask_len <= 32) {
                ip_mask_t ipm;
                ipm.network = addr.s_addr & htonl(0xFFFFFFFF << (32 - mask_len));
                ipm.mask = htonl(0xFFFFFFFF << (32 - mask_len));
                zbx_vector_ip_mask_append(masks, ipm);
                DBG_PRINTF("Added internal network: %s/%d\n", ip_str, mask_len);
            }
        }
        
        token = strtok(NULL, ",");
    }

    free(line_copy);
}

int main(int argc, char *argv[]) {
    unsigned char buffer[BUFFER_SIZE];
    int packet_length;
    const char *interface = "br0";
    
    // support -h / --help anywhere in args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (argc > 1 && *argv[1] != '-') {
        interface = argv[1];
    }
    
    zbx_vector_uint16_create(&detected_protocols);
    zbx_vector_proto_str_create(&detected_apps);
    if (argc > 2) {
        read_line_numbers(argv[2]);
    } else {
        read_line_numbers("-");
    }
    zbx_vector_uint16_sort(&detected_protocols, zbx_default_uint16_compare_func);

    if (argc > 3 && *argv[3] != '-') {
        add_line = argv[3];
    }

    if (argc > 4 && *argv[4] != '-') {
        del_line = argv[4];
    }

    zbx_vector_ip_mask_create(&internal_nets);
    if (argc > 5 && *argv[5] != '-') {
        int_net_line = argv[5];
        ip_mask_parse_line(int_net_line, &internal_nets);
    }
    zbx_vector_ip_ref_create(&ipset_ips);

    if (argc > 6 && *argv[6] != '-') {
        diag_ip = argv[6];
    }

    if (argc > 7 && *argv[7] != '-') {

        if (!(ips = ipset_init())) {
            fprintf(stderr, "Failed to init ipset\n");
            exit(1);
        }

        if (!(ips_session = ipset_session(ips))) {
            fprintf(stderr, "Failed to get session\n");
            ipset_fini(ips);
            exit(1);
        }

        ipset_name = argv[7];

        if (argc > 8 && *argv[8] != '-') {
            ipset_timeout = atoi(argv[8]);
        } else
            ipset_timeout = IDLE_IPSET_TIMEOUT;

        int exists = ipset_set_exists(ipset_name);
        if (exists < 0) {
            fprintf(stderr, "ipset '%s' does not exist, please create it first.\n", ipset_name);
            exit(1);
        } else if (exists == 0 && ipset_add_ipset(ipset_name) < 0) {
            fprintf(stderr, "can't create ipset '%s', please create it first.\n", ipset_name);
            exit(1);
        }
    }

    printf("proto.list DPI Detector (Safe Version) starting...\n");
    printf("Interface: %s\n", interface);
    printf("Max flows: %d\n", MAX_FLOWS);
    printf("Proto count: %d/%d\n", detected_protocols.values_num, detected_apps.values_num);
    printf("add line: %s\n", add_line ? add_line : "none");
    printf("del line: %s\n", del_line ? del_line : "none");
    printf("internal nets[%d]: %s\n", internal_nets.values_num, int_net_line ? int_net_line : "none");
    printf("ipset name: %s timeout:%d\n", ipset_name ? ipset_name : "none", ipset_timeout);

    if (getuid() != 0) {
        fprintf(stderr, "This program requires root privileges\n");
        exit(1);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (init_ndpi() < 0) {
        exit(1);
    }

    raw_socket = init_raw_socket(interface);
    if (raw_socket < 0) {
        fprintf(stderr, "Can't open raw socket: %s\n", strerror(errno));
        cleanup();
        exit(1);
    }

    printf("Starting packet capture...\n");

    while (running) {
        packet_length = recv(raw_socket, buffer, BUFFER_SIZE, 0);

        if (packet_length < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            break;
        }

        if (packet_length > 0) {
            process_packet(buffer, packet_length);
        }
    }

    cleanup();
    printf("End of normal exit\n");
    return 0;
}
