#define CONFNAME CONFDIR "/bgpd.conf"
#define PIDFILE  "/var/run/bgpd.pid"

#define SLEEPTIME	10

#ifndef HAVE_ULONG
typedef unsigned long int ulong;
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

struct bgp_hdr {
	char marker[16];
	uint16_t length;
	char type;
// 1 - OPEN
// 2 - UPDATE
// 3 - NOTIFICATION
// 4 - KEEPALIVE
	char pktdata[4096];
} __attribute__((packed));

struct open_hdr {
	char version;
	uint16_t my_as;
	uint16_t hold_time;
	uint32_t router_id;
	char oparam_len;
} __attribute__((packed));

struct oparam_struct {
	char param_type;
// 1 - AUTH
	char param_length;
} __attribute__((packed));

struct capability {
	char cap_code;
	char cap_length;
} __attribute__((packed));

struct notify {
	char error_code;
	char error_subcode;
	char error_data[1];
} __attribute__((packed));

// UPDATE:
// Unfeasible Routes Length - 2 bytes
// Withdrawn Routes (variable)
// Total Path Attribute Length 2 bytes
// Path Attributes (variable)
// Network Layer Reachability Information (variable)

// Withdrawn Routes:
//  length - 1 byte (0 - 0.0.0.0/0)
//  prefix

extern uint32_t mask[];

extern uint16_t my_as;
extern uint32_t router_id;
extern in_addr_t remote;
extern uint16_t bindport, port;
extern time_t waittime, reconnect_time;
extern uint16_t holdtime;
extern int ballance_cnt, maxdepth;
extern uint16_t remote_as;
extern char perlfile[], plsetclass[], plinitmap[], plbgpup[], plbgpdown[];
extern char plfilter[], plupdate[], plwithdraw[];
extern char pidfile[];
extern int mapinited;

void Log(int level, char *format, ...);
void update(uint32_t prefix, int prefix_len, int community_len, uint32_t *community,
            int aspath_len, uint16_t *aspath);
void withdraw(uint32_t prefix, int prefix_len);
void reset_table(void);
void init_map(int argc, char *argv[]);
void do_initmap(void);
void perlbgpup(void);
void perlbgpdown(void);
void keepalive(void);
int config(char *confname);
