#define CONFNAME CONFDIR "/bgpd.conf"
#define PIDFILE  "/var/run/bgpd.pid"

struct bgp_hdr {
	char marker[16];
	ushort length;
	char type;
// 1 - OPEN
// 2 - UPDATE
// 3 - NOTIFICATION
// 4 - KEEPALIVE
	char pktdata[4096];
};

struct open_hdr {
	char version;
	ushort my_as;
	ushort hold_time;
	ulong router_id;
	char oparam_len;
};

struct oparam_struct {
	char param_type;
// 1 - AUTH
	char param_length;
};

struct capability {
	char cap_code;
	char cap_length;
};

struct notify {
	char error_code;
	char error_subcode;
	char error_data[1];
};

// UPDATE:
// Unfeasible Routes Length - 2 bytes
// Withdrawn Routes (variable)
// Total Path Attribute Length 2 bytes
// Path Attributes (variable)
// Network Layer Reachability Information (variable)

// Withdrawn Routes:
//  length - 1 byte (0 - 0.0.0.0/0)
//  prefix

extern ulong mask[];

extern ushort my_as;
extern ulong router_id, remote;
extern ushort bindport, port;
extern time_t waittime;
extern ushort holdtime;
extern int ballance_cnt, maxdepth;
extern ushort remote_as;
extern char perlfile[], plsetclass[], plinitmap[], plbgpup[];
extern char pidfile[];
extern int mapinited;

void Log(int level, char *format, ...);
void update(ulong prefix, int prefix_len, int community_len, ulong *community,
            int aspath_len, ushort *aspath);
void withdraw(ulong prefix, int prefix_len);
void reset_table(void);
void init_map(int argc, char *argv[]);
void do_initmap(void);
void perlbgpup(void);
void keepalive(void);
int config(char *confname);
