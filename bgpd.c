#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#pragma pack(1)

#include "bgpd.h"

struct bgp_hdr hdr;

enum statustype {IDLE, CONNECT, ACTIVE, OPENSENT, OPENCONFIRM, ESTABLISHED, NO_STATUS }
    status = NO_STATUS;
char *statusstr[] =
    { "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established", "Unknown" };
uint32_t mask[33];
static int terminated = 0, need_reconfig = 0;

static int blockread(int h, void *vbuf, int size)
{
	int res, len=0;
	char *buf = (char *)vbuf;
	while (size > 0)
	{	res = read(h, buf, size);
		if (res < 0)
		{	if (errno == EINTR)
			{
				if (terminated) return -1;
				continue;
			}
			Log(3, "read socket: %s", strerror(errno));
			return res;
		}
		if (res == 0)
		{
			Log(3, "read socket: EOF");
#if 1
			return len;
#else
			continue;
#endif
		}
		len += res;
		size -= res;
		buf += res;
		if (terminated) return len;
	}
	return len;
}

static void setstatus(enum statustype newstatus)
{
	if (newstatus==status) return;
	Log(1, "Status changed to %s", statusstr[newstatus]);
	status=newstatus;
}

static void send_notify(int sock, char error_code, char error_subcode)
{
	struct notify *notify;
	int len;

	hdr.type = 3; /* NOTIFICATION */
	notify = (struct notify *)hdr.pktdata;
	notify->error_code=error_code;
	notify->error_subcode=error_subcode;
	len = sizeof(hdr)-sizeof(hdr.pktdata)+sizeof(*notify)-sizeof(notify->error_data);
	hdr.length=htons(len);
	if (write(sock, &hdr, len) != len)
		Log(0, "Can't send NOTIFICATION message: %s", strerror(errno));
}

static int bgpsession(int sock)
{
	struct open_hdr *open_hdr;
	struct oparam_struct *op;
	struct capability *cap;
	struct mp_cap *mp;
	struct notify *notify;
	fd_set fd;
	struct timeval tv;
	int len, r, i;
	char *p;
	static char str[128];
	time_t hold_time, hold_timer, keepalive_sent, rest_time, curtime;
	uint32_t *community;
	uint32_t *aspath;
	int aspath_len, community_len, prefix_len;
	uint32_t prefix, nexthop;
	// uint32_t localpref, metric;
	// char atomic_aggregate, aspath_type;
	signed char origin;
	int attr_length, withdraw_length, pathattr_length, nlri_length;
	char *withdraw_routes, *pathattr, *nlri;
	char attr_flags, attr_code;
	int wasupdate = 0;
	int as32_support = 0;

	memset(&hdr.marker, 0xff, sizeof(hdr.marker));
	hdr.type = 1; /* OPEN */
	open_hdr = (struct open_hdr *)hdr.pktdata;
	open_hdr->version = 4;
	open_hdr->my_as = htons(my_as < 65536 ? my_as : 23456);
	open_hdr->hold_time = htons(holdtime);
	open_hdr->router_id = router_id;
	op = (struct oparam_struct *)(open_hdr + 1);
	op->param_type = 2; /* Capability */

	cap = (struct capability *)(op + 1);
	cap->cap_code = 65; /* Support 4-byte AS numbers */
	cap->cap_length = 4;
	*(uint32_t *)(cap + 1) = htonl(my_as);
	op->param_length = sizeof(*cap) + cap->cap_length;

	cap = (struct capability *)((char *)(cap + 1) + cap->cap_length);
	cap->cap_code = 1; /* Multiprotocol extension */
	mp = (struct mp_cap *)(cap + 1);
	mp->afi = htons(1);	/* AFI_IP */
	mp->safi = 0;		/* 1 - SAFI_UNICAST */
	mp->data[0] = 1;	/* Length of Next Hop Network Address */
	cap->cap_length = sizeof(*mp) + 1;
	op->param_length += sizeof(*cap) + cap->cap_length;

	open_hdr->oparam_len = sizeof(*op) + op->param_length;
	len = sizeof(hdr) - sizeof(hdr.pktdata) + sizeof(*open_hdr) + open_hdr->oparam_len;
	hdr.length = htons(len);
	if (write(sock, &hdr, len) != len)
	{	Log(0, "Can't write to socket: %s", strerror(errno));
		return 1;
	}
	setstatus(OPENSENT);
	/* waiting for the OPEN message from remote */
	len = blockread(sock, &hdr, sizeof(hdr) - sizeof(hdr.pktdata) + sizeof(*open_hdr));
	if (len < (int)(sizeof(hdr) - sizeof(hdr.pktdata) + sizeof(*open_hdr)))
	{	Log(0, "Can't read from socket: %s", strerror(errno));
		return 1;
	}
	hdr.length = ntohs(hdr.length);
	if (hdr.length > len)
	{	if (blockread(sock, (char *)&hdr + len, hdr.length - len) < hdr.length - len)
		{	Log(0, "Can't read from socket: %s", strerror(errno));
			return 1;
		}
	}
	/* check received OPEN message */
	for (i = 0; i < sizeof(hdr.marker); i++)
	{	if (hdr.marker[i] != 0xff)
		{	send_notify(sock, 1, 1); /* Connection Not Synchronized */
			Log(0, "Bad marker");
			return 1;
		}
	}
	if (hdr.type != 1)
	{	send_notify(sock, 1, 3); /* Bad Message Type */
		Log(0, "No OPEN message received");
		return 1;
	}
	if (hdr.length > 4096)
	{	send_notify(sock, 1, 2); /* Bad Message Length */
		Log(0, "Too long message (%u bytes)", hdr.length);
		return 1;
	}
	if (open_hdr->version != 4)
	{	send_notify(sock, 2, 1); /* Unsupported version number */
		Log(0, "Unsupported version %d", open_hdr->version);
		return 1;
	}
	if (ntohs(open_hdr->my_as) != (remote_as < 65536 ? remote_as : 23456))
	{	send_notify(sock, 2, 2); /* Bad peer AS */
		Log(0, "Remote AS %u, not %u!", ntohs(open_hdr->my_as), remote_as);
		return 1;
	}
	hold_time = ntohs(open_hdr->hold_time);
	if (hold_time > 0 && hold_time < 3)
	{	send_notify(sock, 2, 6); /* Unacceptable hold time */
		Log(0, "Unacceptable hold time %u sec", hold_time);
		return 1;
	}
	if (hold_time == 0 || (hold_time > holdtime && holdtime > 0))
		hold_time = holdtime;
	/* check for open params */
	if (open_hdr->oparam_len > 0)
	{
#if 0
		send_notify(sock, 2, 4); /* Unsupported Optional Parameter */
		Log(0, "Unsupported optional parameter type %u",
		    *(char *)(open_hdr+1));
		return 1;
#else
		op = (struct oparam_struct *)(open_hdr + 1);
		len = open_hdr->oparam_len;
		while (len > 0)
		{	char str[80];
			if (op->param_type == 2)
			{	/* Capability */
				cap = (struct capability *)(op + 1);
				if (cap->cap_code == 1)
				{	Log(5, "Remote supports some Multiprotocol extensions");
				} else if (cap->cap_code == 2) /* Route Refresh Capability */
				{	Log(5, "Remote supports route refresh");
				} else if (cap->cap_code == 64)
				{	Log(5, "Remote supports graceful restart");
				} else if (cap->cap_code == 65)
				{	Log(5, "Remote supports 4-byte AS numbers");
					if (cap->cap_length != 4)
					{
						Log(1, "Bad AS4 support capability length %u, expected 4", cap->cap_length);
						send_notify(sock, 2, 4); /* Unsupported Optional Parameter */
						return 1;
					}
					if (ntohl(*(uint32_t *)(cap + 1)) != remote_as)
					{	Log(0, "Remote as %u, not %u!", ntohl(*(uint32_t *)(cap + 1)), remote_as);
						send_notify(sock, 2, 2); /* Bad peer AS */
						return 1;
					}
					as32_support = 1;
				} else if (cap->cap_code == 70)
				{	Log(5, "Remote supports enhanced route refresh");
				} else if (cap->cap_code == 128)
				{	Log(5, "Remote supports route refresh (old cisco router)");
				} else
				{	str[0] = '\0';
					for (i = 0; i < cap->cap_length && i < (sizeof(str) - 1) / 2; i++)
						sprintf(str + i * 2, "%02x", ((char *)(cap + 1))[i]);
					Log(3, "Unknown capability code 0x%02x len %u '%s'", cap->cap_code, cap->cap_length, str);
				}
			} else
			{	str[0] = '\0';
				for (i = 0; i < op->param_length && i < (sizeof(str) - 1)/2; i++)
					sprintf(str + i*2, "%02x", ((char *)(op + 1))[i]);
				Log(1, "Unsupported open parameter type %u len %u: %s",
				    op->param_type, op->param_length, str);
				send_notify(sock, 2, 4); /* Unsupported Optional Parameter */
				return 1;
			}
			len -= (op->param_length + 2);
			op = (struct oparam_struct *)((char *)op + op->param_length + 2);
		}
#endif
	}
	Log(2, "Remote AS: %u, remote router-id %s",
	    remote_as, inet_ntoa(*(struct in_addr *)&open_hdr->router_id));
	/* send OpenConfirm */
	hdr.type = 4; /* KEEPALIVE */
	len = sizeof(hdr) - sizeof(hdr.pktdata);
	hdr.length = htons(len);
	keepalive_sent = time(NULL);
	if (write(sock, &hdr, len) != len)
	{	Log(0, "Can't write to socket: %s", strerror(errno));
		return 1;
	}
	// Log(4, "KeepAlive sent");
	setstatus(OPENCONFIRM);
	/* main loop - receiving messages and send keepalives */
	hold_timer = time(NULL);
	need_reconfig = 0;
	while (1)
	{
		if (terminated) break;
#ifdef SOFT_RECONFIG
		if (need_reconfig)
		{
			reconfig();
			need_reconfig = 0;
		}
#endif
		curtime = time(NULL);
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		tv.tv_sec = hold_time / 3;
		tv.tv_usec = 0;
		rest_time = curtime - keepalive_sent;
		if (hold_time)
		{	if (rest_time >= hold_time / 3)
				goto send_keepalive;
			tv.tv_sec = hold_time / 3 - rest_time;
		} else
			tv.tv_sec = 0;
		rest_time = curtime - hold_timer;
		if (hold_time && hold_time <= rest_time)
		{	send_notify(sock, 4, 0); /* Hold timer expired */
			Log(0, "No messages within hold time %u sec", hold_time);
			return 1;
		}
		if (hold_time && hold_time - rest_time < hold_time / 3)
			tv.tv_sec = hold_time - rest_time;
		r = select(sock + 1, &fd, NULL, NULL, &tv);
		if (terminated) break;
		curtime = time(NULL);
		if (r == 0)
		{	/* send KEEPALIVE */
send_keepalive:
#if 1
			for (i = 0; i < sizeof(hdr.marker); i++)
				if (hdr.marker[i] != 0xff)
				{	send_notify(sock, 1, 1); /* Connection Not Synchronized */
					Log(0, "Bad my marker");
					for (i = 0; i < len && i < (sizeof(str) - 1) / 2; i++)
						sprintf(str + i * 2, "%02x", *(((char *)&hdr) + i));
					Log(0, "Packet header: %s", str);
					//return 1;
					memset(hdr.marker, 0xff, sizeof(hdr.marker));
					break;
				}
#endif
			keepalive_sent = time(NULL);
			len = sizeof(hdr) - sizeof(hdr.pktdata);
			hdr.type = 4;
			hdr.length = htons(len);
			if (write(sock, &hdr, len) != len)
			{	Log(0, "Can't write to socket: %s", strerror(errno));
				return 1;
			}
			// Log(4, "KeepAlive sent");
			keepalive(1);
			continue;
		}
		if (r == -1)
		{	if (errno == EINTR)
				continue;
			Log(0, "Select error: %s", strerror(errno));
			return 1;
		}
		/* message arrived */
		len = blockread(sock, &hdr, sizeof(hdr) - sizeof(hdr.pktdata));
		if (terminated) break;
		if (len != sizeof(hdr) - sizeof(hdr.pktdata))
		{	Log(0, "Can't read from socket: %s", strerror(errno));
			return 1;
		}
		for (i = 0; i < sizeof(hdr.marker); i++)
		{
			if (hdr.marker[i] != 0xff)
			{	send_notify(sock, 1, 1); /* Connection Not Synchronized */
				Log(0, "Bad marker");
				for (i = 0; i < len && i < (sizeof(str) - 1) / 2; i++)
					sprintf(str + i * 2, "%02x", *(((char *)&hdr) + i));
				Log(0, "Received packet header: %s", str);
				// return 1;
				break;
			}
		}
		hdr.length = ntohs(hdr.length);
		if (hdr.length < len || hdr.length > 4096)
		{	send_notify(sock, 1, 2); /* Bad Message Length */
			Log(0, "Bad message length (%u bytes)", hdr.length);
			return 1;
		}
		if (hdr.length > len)
		{	if (blockread(sock, hdr.pktdata, hdr.length - len) != hdr.length - len)
			{	Log(0, "Can't read from socket: %s", strerror(errno));
				return 1;
			}
		}
		if (hdr.type < 2 || hdr.type > 5)
		{	send_notify(sock, 1, 3); /* Unsupported message type */
			Log(0, "Unknown message type %u", hdr.type);
			return 1;
		}
		if (hdr.type == 3)
		{	/* NOTIFY */
			for (i = 0; i < hdr.length - (sizeof(hdr) - sizeof(hdr.pktdata)) && i < (sizeof(str) - 1) / 2; i++)
				sprintf(str + i * 2, "%02x", hdr.pktdata[i]);
			Log(0, "Received packet data: %s", str);

			notify = (struct notify *)hdr.pktdata;
			hdr.pktdata[hdr.length - (sizeof(hdr) - sizeof(hdr.pktdata))] = '\0';
			Log(0, "NOTIFICATION message received, error code %u, subcode %u, data \'%s\'", notify->error_code, notify->error_subcode, notify->error_data);
			return 1;
		}
		if (hdr.type == 5)
		{	/* ROUTE_REFRESH */
		}
		if (hdr.type != 4 && status == OPENCONFIRM)
		{	send_notify(sock, 1, 3); /* Unsupported message type */
			Log(0, "No OpenConfirm message", hdr.type);
			return 1;
		}
		hold_timer = time(NULL);
		if (hdr.type == 4)
		{	if (status == OPENCONFIRM)
				setstatus(ESTABLISHED);
			Log(9, "hdr.length %d", hdr.length);
			keepalive(0);
			continue;
		}
		/* process UPDATE message */
		if (!wasupdate)
		{
			reset_table();
			do_initmap();
			perlbgpup();
			mapinited = 0;
			wasupdate = 1;
		}
		withdraw_length = ntohs(*(uint16_t *)(hdr.pktdata));
		withdraw_routes = hdr.pktdata + 2;
		pathattr_length = ntohs(*(uint16_t *)(withdraw_routes + withdraw_length));
		pathattr = withdraw_routes + withdraw_length + 2;
		nlri_length = hdr.length - 23 - withdraw_length - pathattr_length;
		nlri = pathattr + pathattr_length;
		Log(5, "Received UPDATE message");
//		Log(5, "Received UPDATE message, withdraw_length %u, pathattr_length %u, nlri_length %u", withdraw_length, pathattr_length, nlri_length);
//for (i=0; i<hdr.length; i++) printf("%02X", ((char *)&hdr)[i]); printf("\n");
		while (withdraw_length > 0)
		{
			prefix_len = *withdraw_routes++;
			prefix = *(uint32_t *)withdraw_routes;
			prefix &= mask[prefix_len];
			withdraw_routes += (prefix_len + 7) / 8;
			withdraw_length -= 1 + (prefix_len + 7) / 8;
			withdraw(prefix, prefix_len);
		}
		origin = -1;
		aspath = NULL;
		community = NULL;
		aspath_len = community_len = 0;
		nexthop = 0;
		// metric = localpref = atomic_aggregate = 0;
		p = NULL;
		while (pathattr_length > 0)
		{
			if (p) pathattr = p;
			attr_flags = *pathattr++;
			attr_code  = *pathattr++;
			if (attr_flags & 0x10) /* extended length */
			{	attr_length = ntohs(*(uint16_t *)pathattr);
				pathattr += 2;
				pathattr_length--;
			} else
			{	attr_length = *pathattr++;
			}
			pathattr_length -= 3 + attr_length;
			p = pathattr + attr_length;
			// Log(4, "Attr code %u, flags 0x%02X, length %u", attr_code, attr_flags, attr_length);
			if (attr_code == 1)
			{	origin = *pathattr;
				continue;
			}
			if (attr_code == 2)
			{	// aspath_type = *pathattr++;
				aspath_len = *pathattr++;
				if (attr_length != aspath_len * (as32_support ? 4 : 2) + 2)
				{
					int aspath_len_calc = (attr_length - 2) / (as32_support ? 4 : 2);
					Log(4, "aspath length %u, should be %u", aspath_len, aspath_len_calc);
					if (aspath_len > aspath_len_calc)
					{
						Log(1, "Aspath length adjusted, %u to %u", aspath_len, aspath_len_calc);
						aspath_len = aspath_len_calc;
					}
				}

				if (as32_support)
					aspath = (uint32_t *)pathattr;
				else
				{
					static int aspath_buf_len = 0;
					static uint32_t *aspath_buf = NULL;
					uint16_t *aspath16 = (uint16_t *)pathattr;

					if (aspath_len > aspath_buf_len)
					{
						aspath_buf_len = aspath_len;
						aspath_buf = realloc(aspath_buf, aspath_buf_len * sizeof(*aspath));
					}
					for (i = 0; i < aspath_len; i++)
						aspath_buf[i] = htonl(ntohs(aspath16[i]));
					aspath = aspath_buf;
				}
				continue;
			}
			if (attr_code == 3)
			{	nexthop = *(uint32_t *)pathattr;
				continue;
			}
			if (attr_code == 4)
			{	// metric = ntohl(*(uint32_t *)pathattr);
				continue;
			}
			if (attr_code == 5)
			{	// localpref = ntohl(*(uint32_t *)pathattr);
				continue;
			}
			if (attr_code == 6)
			{	// atomic_aggregate = 1;
				continue;
			}
			if (attr_code == 7)
			{	/* aggregator - ignore */
				continue;
			}
			if (attr_code == 8)
			{
				community = (uint32_t *)pathattr;
				community_len = attr_length / 4;
				continue;
			}
			if (attr_code == 10)
			{	/* RR cluster ID, ignore */
				continue;
			}
			if (attr_code == 17)
			{	/* AS4_PATH */
				if (as32_support)
					Log(1, "AS4_PATH optional attribute ignored from AS4-supported speaker");
				else
				{
					// aspath_type = *pathattr++;
					i = *pathattr++;
					if (i <= aspath_len)
						memcpy(aspath + aspath_len - i, pathattr, i * 4);
					Log(1, "AS4_PATH optional attribute used");
				}
				continue;
			}
			if (attr_code == 18)
			{	/* AS4_AGGREGATOR */
				Log(1, "AS4_AGGREGATOR optional attribute ignored");
				continue;
			}
			if ((attr_flags & 0x80) == 0)
			{	send_notify(sock, 4, 2); /* Unrecognized well-known attribute */
				Log(0, "Unrecognized well-known attribute type %u length %u", attr_code, attr_length);
				return 1;
			}
			for (i = 0; i < attr_length && i < (sizeof(str) - 1) / 2; i++)
				sprintf(str + i * 2, "%02x", *pathattr++);
			Log(3, "Unrecognized optional attribute type %u length %u value %s", attr_code, attr_length, str);
		}
		if (nlri_length == 0)
			continue;
		if (origin == (char)-1 || aspath == NULL)
		{	send_notify(sock, 4, 3); /* Missing Well-known Attribute */
			Log(0, "Origin missed in UPDATE packet!");
			return 1;
		}
		if ((unsigned char)origin > 2)
		{	send_notify(sock, 4, 6); /* Invalid ORIGIN Attribute */
			Log(0, "Invalid ORIGIN Attribute %u", origin);
			return 1;
		}
		/* parse nlri */
		while (nlri_length > 0)
		{
			prefix_len = *nlri++;
			prefix=*(uint32_t *)nlri;
			prefix &= mask[prefix_len];
			nlri += (prefix_len + 7) / 8;
			nlri_length -= 1 + (prefix_len + 7) / 8;
			//Log(5, "Process prefix %s/%u, rest nlri_length %u",
			//    inet_ntoa(*(struct in_addr *)&prefix), prefix_len,
			//    nlri_length);
			update(prefix, prefix_len, community_len, community,
			       aspath_len, aspath, nexthop);
		}
		update_done();
	}
	send_notify(sock, 6, 4); /* administrative reset */
	return 1;
}


#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
	int i;
	if (!nochdir) chdir("/");
	if (!noclose)
	{
		i = open("/dev/null", O_RDONLY);
		if (i != -1)
		{	if (i > 0) dup2(i, 0);
			close(i);
		}
		i = open("/dev/null", O_WRONLY);
		if (i != -1)
		{	if (i > 1) dup2(i, 1);
			if (i > 2) dup2(i, 2);
			close(i);
		}
	}
	if ((i = fork()) == -1) return -1;
	if (i > 0) exit(0);
	setsid();
	return 0;
}
#endif

int usage(void)
{
	printf("BGP daemon      " __DATE__ "\n");
	printf("    Usage:\n");
	printf("bgpd [-d] [config]\n");
	printf("  -d  - daemonize\n");
	return 0;
}

void rmpid(void)
{
	unlink(pidfile);
}


static void sighnd(int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
	{
		Log(1, "Program terminated by signal %u", signo);
		terminated = 1;
	}
#ifdef SOFT_RECONFIG
	else if (signo == SIGHUP)
	{
		Log(1, "Received signal SIGHUP, perform soft reconfiguration");
		need_reconfig = 1;
	}
#endif
}

int main(int argc, char *argv[])
{
	int sockin, sockout, newsock;
	struct sockaddr_in serv_addr, conn_addr, sin, client_addr;
	socklen_t client_addr_len;
	fd_set fdr, fdw, fde;
	struct timeval tv;
	time_t select_wait, selectstart, last_out, curtime;
	int i, r, daemonize;
	char *confname;

	mask[0] = 0;
	for (i = 1; i <= 32; i++)
		mask[i] = htonl(0xfffffffful << (32 - i));
	confname = CONFNAME;
	daemonize = 0;
	while ((i = getopt(argc, argv, "dh?")) != -1)
	{
		switch (i)
		{
			case 'd':
				daemonize = 1; break;
			case 'h':
			case '?':
				usage(); return 1;
			default:
				fprintf(stderr,"Unknown option -%c\n", (char)i);
				usage();
				return 2;
		}
	}
	if (argc > optind)
		confname = argv[optind];
	if (config(confname))
		exit(3);
	if (daemonize)
		if (daemon(0, 0) != 0)
		{	fprintf(stderr, "Can't daemonize: %s\n", strerror(errno));
			exit(1);
		}
	if (pidfile[0])
	{
		FILE *f = fopen(pidfile, "w");
		if (f)
		{
			fprintf(f, "%u\n", (unsigned)getpid());
			fclose(f);
			atexit(rmpid);
		} else
			fprintf(stderr, "Can't create %s: %s\n", pidfile, strerror(errno));
	}
	setstatus(IDLE);
	signal(SIGINT, sighnd);
	signal(SIGTERM, sighnd);
	signal(SIGHUP, sighnd);
	init_map(argc, argv);
	/* open listening socket */
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_port = bindport;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
	/* client socket */
	memset(&conn_addr, 0, sizeof(conn_addr));
	conn_addr.sin_port = bindport;
	conn_addr.sin_family = AF_INET;
	conn_addr.sin_addr.s_addr = htonl (INADDR_ANY);
	sockin = sockout = -1;
	last_out = 0;

	while (1)
	{
		if (terminated) exit(3);
		curtime = time(NULL);
		if (sockin == -1)
		{	if ((sockin = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			{	Log (0, "socket: %s", strerror(errno));
				exit(1);
			}
			if (setsockopt(sockin, SOL_SOCKET, SO_REUSEADDR,
			               (char *) &i, sizeof i) == -1)
				Log (1, "setsockopt(SO_REUSEADDR): %s", strerror(errno));
			if (bind(sockin, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
			{	Log (0, "bind: %s", strerror(errno));
				close(sockin);
				sockin = -1;
			} else
				/* waiting for incoming connection */
				listen(sockin, 5);
		}

		setstatus(ACTIVE);
		/* try to connect */
		if (sockout == -1 && time(NULL) - last_out >= reconnect_time)
		{
			setstatus(CONNECT);
			if ((sockout = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			{	Log (0, "socket: %s", strerror(errno));
				exit(1);
			}
#if 0
			if (setsockopt(sockout, SOL_SOCKET, SO_REUSEADDR,
			               (char *) &i, sizeof i) == -1)
				Log (1, "setsockopt(SO_REUSEADDR): %s", strerror(errno));
			if (bind(sockout, (struct sockaddr *)&conn_addr, sizeof(conn_addr)) != 0)
			{	Log (0, "bind: %s", strerror(errno));
				close(sockout);
				sockout=-1;
				exit(1);
			}
#endif
			sin.sin_addr.s_addr = remote;
			sin.sin_port = port;
			sin.sin_family = AF_INET;
			r = fcntl (sockout, F_GETFL, 0) ;
			if (r >= 0)
				r = fcntl (sockout, F_SETFL, r | O_NONBLOCK) ;
			last_out = time(NULL);
			if (connect(sockout, (struct sockaddr *)&sin, sizeof(sin)))
			{	
				if (errno != EINPROGRESS)
				{	Log(0, "Can't connect: %s", strerror(errno));
					close(sockout);
					sockout=-1;
					setstatus(ACTIVE);
				}
			}
		}
		select_wait = waittime;
		if (select_wait + curtime > last_out + reconnect_time && sockout == -1)
			select_wait = last_out + reconnect_time - curtime;
repselect:
		if (terminated) exit(3);
		if (sockin == -1 && sockout == -1)
		{	sleep(select_wait);
			curtime = time(NULL);
			continue;
		}
		FD_ZERO(&fdr);
		FD_ZERO(&fdw);
		FD_ZERO(&fde);
		if (sockin != -1)
			FD_SET(sockin, &fdr);
		if (sockout != -1)
		{	FD_SET(sockout, &fdw);
			FD_SET(sockout, &fde);
			setstatus(CONNECT);
		} else
			setstatus(ACTIVE);
		tv.tv_sec = select_wait;
		tv.tv_usec = 0;
		selectstart = curtime;
		r = select(((sockin > sockout) ? sockin : sockout) + 1, &fdr, &fdw, &fde, &tv);
		if (terminated) exit(3);
		curtime = time(NULL);
		if (r == -1)
		{	if (errno == EINTR)
				continue;
			Log(0, "Select: %s", strerror(errno));
			setstatus(IDLE);
			sleep(select_wait - (selectstart - curtime));
		} else if (r == 0)
		{	Log(5, "Select: timeout");
			setstatus(IDLE);
		} else
		{	if (sockout != -1 && FD_ISSET(sockout, &fde))
			{
				Log(5, "Select: connect() exception");
errconnect:
				close(sockout);
				sockout=-1;
				select_wait -= curtime - selectstart;
				if (r == 1 && select_wait > 0) goto repselect;
				last_out = curtime;
			}
			if (sockout != -1 && FD_ISSET(sockout, &fdw))
			{	int rr = 0;
			       	socklen_t i = sizeof(r);
				if (getsockopt(sockout, SOL_SOCKET, SO_ERROR,
				               &rr, &i))
				{	Log(0, "getsockopt: %s", strerror(errno));
					goto errconnect;
				}
				if (rr)
				{	Log(0, "connect(): %s", strerror(rr));
					goto errconnect;
				}
				/* connected */
				setstatus(CONNECT);
				rr = fcntl(sockout, F_GETFL, 0) ;
				if (rr >= 0)
					rr = fcntl(sockout, F_SETFL, rr & ~O_NONBLOCK) ;
				if (sockin != -1) close(sockin);
				sockin = -1;
				Log(4, "Outgoing bgp session");
				bgpsession(sockout);
				reset_table();
			}
			else if (sockin != -1 && FD_ISSET(sockin, &fdr))
			{	/* incoming connection */
				setstatus(CONNECT);
				if (sockout != -1) close(sockout);
				sockout = -1;
				newsock = accept(sockin, (struct sockaddr *)&client_addr, &client_addr_len);
				if (newsock == -1)
				{	Log(0, "Accept: %s", strerror(errno));
				} else
				{	/* check for remote */
					if (client_addr.sin_addr.s_addr != sin.sin_addr.s_addr)
					{	Log(0, "Rejecting connection from %s", inet_ntoa(client_addr.sin_addr));
						close(newsock);
					} else
					{	if (sockout) close(sockout);
						if (sockin) close(sockin);
						sockout = sockin = -1;
						Log(4, "Incoming bgp session");
						bgpsession(newsock);
						close(newsock);
						reset_table();
					}
				}
			}
		}
		if (sockout != -1)
		{	close(sockout);
			sockout = -1;
			last_out = curtime;
		}
		setstatus(IDLE);
	}
}

