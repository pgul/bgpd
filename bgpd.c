#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
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
unsigned long mask[33];

static int blockread(int h, void *buf, int size)
{
	int res, len=0;
	while (size>0)
	{	res = read(h, buf, size);
		if (res<0)
		{	Log(3, "read socket: %s", strerror(errno));
			return res;
		}
		if (res==0)
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
		(char *)buf += res;
	}
	return len;
}

void Log(int level, char *format, ...)
{
	time_t t;
	struct tm *tm;
	char str[64];
	va_list ap;
	va_start(ap, format);
	t = time(NULL);
	tm = localtime(&t);
	strftime(str, sizeof(str), "%d/%m/%Y %T", tm);
	fprintf(stdout, "%u %s ", level, str);
	vfprintf(stdout, format, ap);
	fprintf(stdout, "\n");
	va_end(ap);
	fflush(stdout);
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
	struct notify *notify;
	fd_set fd;
	struct timeval tv;
	int len, r, i;
	char *p;
	static char str[128];
	time_t hold_time, hold_timer, keepalive_sent, rest_time;
	unsigned long *community;
	unsigned short *aspath;
	int aspath_len, community_len, prefix_len;
	unsigned long prefix, nexthop;
	unsigned long localpref, metric;
	char atomic_aggregate, origin, aspath_type;
	int attr_length, withdraw_length, pathattr_length, nlri_length;
	char *withdraw_routes, *pathattr, *nlri;
	char attr_flags, attr_code;
	int wasupdate=0;

	memset(&hdr.marker, 0xff, sizeof(hdr.marker));
	hdr.type = 1; /* OPEN */
	open_hdr = (struct open_hdr *)hdr.pktdata;
	open_hdr->version = 4;
	open_hdr->my_as = htons(my_as);
	open_hdr->hold_time = htons(holdtime);
	open_hdr->router_id = router_id;
	open_hdr->oparam_len = 0;
	len = sizeof(hdr)-sizeof(hdr.pktdata)+sizeof(*open_hdr);
	hdr.length = htons(len);
	if (write(sock, &hdr, len) != len)
	{	Log(0, "Can't write to socket: %s", strerror(errno));
		return 1;
	}
	setstatus(OPENSENT);
	/* waiting for the OPEN message from remote */
	len = blockread(sock, &hdr, sizeof(hdr)-sizeof(hdr.pktdata)+sizeof(*open_hdr));
	if (len<(int)(sizeof(hdr)-sizeof(hdr.pktdata)+sizeof(*open_hdr)))
	{	Log(0, "Can't read from socket: %s", strerror(errno));
		return 1;
	}
	hdr.length = ntohs(hdr.length);
	if (hdr.length>len)
	{	if (blockread(sock, (char *)&hdr+len, hdr.length-len)<hdr.length-len)
		{	Log(0, "Can't read from socket: %s", strerror(errno));
			return 1;
		}
	}
	/* check received OPEN message */
	for (i=0; i<sizeof(hdr.marker); i++)
	{	if (hdr.marker[i]!=0xff)
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
	if (ntohs(open_hdr->my_as) != remote_as)
	{	send_notify(sock, 2, 2); /* Bad peer AS */
		Log(0, "Remote as %u, not %u!", ntohs(open_hdr->my_as), remote_as);
		return 1;
	}
	hold_time = ntohs(open_hdr->hold_time);
	if (hold_time>0 && hold_time<3)
	{	send_notify(sock, 2, 6); /* Unacceptable hold time */
		Log(0, "Unacceptable hold time %u sec", hold_time);
		return 1;
	}
	if (hold_time==0 || (hold_time>holdtime && holdtime>0))
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
		op=(struct oparam_struct *)(open_hdr+1);
		len = open_hdr->oparam_len;
		while (len>0)
		{	char str[80];
			if (op->param_type==2)
			{	/* Capability */
				cap = (struct capability *)(op+1);
				if (cap->cap_code==2) /* Route Refresh Capability */
				{	Log(5, "Remote REFRESH capable");
				} else
				{	str[0]='\0';
					for (i=0; i<cap->cap_length && i<(sizeof(str)-1)/2; i++)
						sprintf(str+i*2, "%02x", ((char *)(cap+1))[i]);
					Log(3, "Unknown capability code 0x%02x len %u '%s'", cap->cap_code, cap->cap_length, str);
				}
			} else
			{	str[0]='\0';
				for (i=0; i<op->param_length && i<(sizeof(str)-1)/2; i++)
					sprintf(str+i*2, "%02x", ((char *)(op+1))[i]);
				Log(1, "Unsupported open parameter type %u len %u: %s",
				    op->param_type, op->param_length, str);
				send_notify(sock, 2, 4); /* Unsupported Optional Parameter */
				return 1;
			}
			len -= (op->param_length+2);
			op = (struct oparam_struct *)((char *)op+op->param_length+2);
		}
#endif
	}
	Log(2, "Remote AS: %u, remote router-id %s",
	    remote_as, inet_ntoa(*((struct in_addr *)&open_hdr->router_id)));
	/* send OpenConfirm */
	hdr.type = 4; /* KEEPALIVE */
	len = sizeof(hdr) - sizeof(hdr.pktdata);
	hdr.length = htons(len);
	keepalive_sent = time(NULL);
	if (write(sock, &hdr, len) != len)
	{	Log(0, "Can't write to socket: %s", strerror(errno));
		return 1;
	}
	//Log(4, "KeepAlive sent");
	setstatus(OPENCONFIRM);
	/* main loop - receiving messages and send keepalives */
	hold_timer = time(NULL);
	while (1)
	{
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		tv.tv_sec = hold_time/3;
		tv.tv_usec=0;
		rest_time = time(NULL)-keepalive_sent;
		if (hold_time)
		{	if (rest_time >= hold_time/3)
				goto send_keepalive;
			tv.tv_sec = hold_time/3-rest_time;
		} else
			tv.tv_sec = 0;
		rest_time = time(NULL)-hold_timer;
		if (hold_time && hold_time<=rest_time)
		{	send_notify(sock, 4, 0); /* Hold timer expired */
			Log(0, "No messages within hold time %u sec", hold_time);
			return 1;
		}
		if (hold_time && hold_time-rest_time<hold_time/3)
			tv.tv_sec = hold_time-rest_time;
		r=select(sock+1, &fd, NULL, NULL, &tv);
		if (r==0)
		{	/* send KEEPALIVE */
send_keepalive:
#if 1
			for (i=0; i<sizeof(hdr.marker); i++)
				if (hdr.marker[i]!=0xff)
				{	send_notify(sock, 1, 1); /* Connection Not Synchronized */
					Log(0, "Bad my marker");
					for (i=0; i<len && i<(sizeof(str)-1)/2; i++)
						sprintf(str+i*2, "%02x", *(((char *)&hdr)+i));
					Log(0, "Packet header: %s", str);
					//return 1;
					memset(hdr.marker, 0xff, sizeof(hdr.marker));
					break;
				}
#endif
			keepalive_sent = time(NULL);
			len = sizeof(hdr)-sizeof(hdr.pktdata);
			hdr.type = 4;
			hdr.length = htons(len);
			if (write(sock, &hdr, len) != len)
			{	Log(0, "Can't write to socket: %s", strerror(errno));
				return 1;
			}
			//Log(4, "KeepAlive sent");
			keepalive();
			continue;
		}
		if (r==-1)
		{	Log(0, "Select error: %s", strerror(errno));
			return 1;
		}
		/* message arrived */
		len = blockread(sock, &hdr, sizeof(hdr)-sizeof(hdr.pktdata));
		if (len != sizeof(hdr)-sizeof(hdr.pktdata))
		{	Log(0, "Can't read from socket: %s", strerror(errno));
			return 1;
		}
		for (i=0; i<sizeof(hdr.marker); i++)
			if (hdr.marker[i]!=0xff)
			{	send_notify(sock, 1, 1); /* Connection Not Synchronized */
				Log(0, "Bad marker");
				for (i=0; i<len && i<(sizeof(str)-1)/2; i++)
					sprintf(str+i*2, "%02x", *(((char *)&hdr)+i));
				Log(0, "Received packet header: %s", str);
				//return 1;
				break;
			}
		hdr.length = ntohs(hdr.length);
		if (hdr.length<len || hdr.length>4096)
		{	send_notify(sock, 1, 2); /* Bad Message Length */
			Log(0, "Bad message length (%u bytes)", hdr.length);
			return 1;
		}
		if (hdr.length>len)
		{	if (blockread(sock, hdr.pktdata, hdr.length-len) != hdr.length-len)
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
			for (i=0; i<hdr.length-(sizeof(hdr)-sizeof(hdr.pktdata)) && i<(sizeof(str)-1)/2; i++)
				sprintf(str+i*2, "%02x", hdr.pktdata[i]);
			Log(0, "Received packet data: %s", str);

			notify = (struct notify *)hdr.pktdata;
			hdr.pktdata[hdr.length-(sizeof(hdr)-sizeof(hdr.pktdata))] = '\0';
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
			Log(4, "KeepAlive received");
			Log(9, "hdr.length %d", hdr.length);
			continue;
		}
		/* process UPDATE message */
		if (!wasupdate)
		{
			reset_table();
			do_initmap();
			perlbgpup();
			mapinited=0;
			wasupdate=1;
		}
		withdraw_length = ntohs(*(ushort *)(hdr.pktdata));
		withdraw_routes = hdr.pktdata+2;
		pathattr_length = ntohs(*(ushort *)(withdraw_routes+withdraw_length));
		pathattr = withdraw_routes+withdraw_length+2;
		nlri_length = hdr.length-23-withdraw_length-pathattr_length;
		nlri = pathattr+pathattr_length;
		Log(5, "Received UPDATE message");
//		Log(5, "Received UPDATE message, withdraw_length %u, pathattr_length %u, nlri_length %u", withdraw_length, pathattr_length, nlri_length);
//for (i=0; i<hdr.length; i++) printf("%02X", ((char *)&hdr)[i]); printf("\n");
		while (withdraw_length>0)
		{
			prefix_len=*withdraw_routes++;
			prefix=*(ulong *)withdraw_routes;
			prefix &= mask[prefix_len];
			withdraw_routes += (prefix_len+7)/8;
			withdraw_length -= 1+(prefix_len+7)/8;
			withdraw(prefix, prefix_len);
		}
		origin=-1;
		aspath=NULL;
		community=NULL;
		aspath_len=community_len=0;
		nexthop=0;
		metric=localpref=atomic_aggregate=0;
		p=NULL;
		while (pathattr_length>0)
		{
			if (p) pathattr=p;
			attr_flags = *pathattr++;
			attr_code  = *pathattr++;
			if (attr_flags & 0x10) /* extended length */
			{	attr_length = ntohs(*(ushort *)pathattr);
				pathattr+=2;
				pathattr_length--;
			} else
			{	attr_length = *pathattr++;
			}
			pathattr_length-=3+attr_length;
			p=pathattr+attr_length;
			// Log(4, "Attr code %u, flags 0x%02X, length %u", attr_code, attr_flags, attr_length);
			if (attr_code == 1)
			{	origin = *pathattr;
				continue;
			}
			if (attr_code == 2)
			{	aspath_type=*pathattr++;
				aspath_len=*pathattr++;
				aspath=(ushort *)pathattr;
				continue;
			}
			if (attr_code == 3)
			{	nexthop=*(ulong *)pathattr;
				continue;
			}
			if (attr_code == 4)
			{	metric=ntohl(*(ulong *)pathattr);
				continue;
			}
			if (attr_code == 5)
			{	localpref=ntohl(*(ulong *)pathattr);
				continue;
			}
			if (attr_code == 6)
			{	atomic_aggregate = 1;
				continue;
			}
			if (attr_code == 7)
			{	/* aggregator - ignore */
				continue;
			}
			if (attr_code == 8)
			{
				community=(ulong *)pathattr;
				community_len=attr_length/4;
				continue;
			}
			if ((attr_flags & 0x40) == 0)
			{	send_notify(sock, 4, 2); /* Unrecognized well-known attribute */
				Log(0, "Unrecognized well-known attribute type %u length %u", attr_code, attr_length);
				return 1;
			}
			for (i=0; i<attr_length && i<(sizeof(str)-1)/2; i++)
				sprintf(str+i*2, "%02x", *pathattr++);
			Log(3, "Unrecognized optional attribute type %u length %u value %s", attr_code, attr_length, str);
		}
		if (nlri_length == 0)
			continue;
		if (origin == (char)-1 || aspath==NULL)
		{	send_notify(sock, 4, 3); /* Missing Well-known Attribute */
			Log(0, "Origin missed in UPDATE packet!");
			return 1;
		}
		if ((unsigned char)origin>2)
		{	send_notify(sock, 4, 6); /* Invalid ORIGIN Attribute */
			Log(0, "Invalid ORIGIN Attribute %u", origin);
			return 1;
		}
		/* parse nlri */
		while (nlri_length>0)
		{
			prefix_len=*nlri++;
			prefix=*(ulong *)nlri;
			prefix &= mask[prefix_len];
			nlri += (prefix_len+7)/8;
			nlri_length -= 1+(prefix_len+7)/8;
			//Log(5, "Process prefix %s/%u, rest nlri_length %u",
			//    inet_ntoa(*(struct in_addr *)&prefix), prefix_len,
			//    nlri_length);
			update(prefix, prefix_len, community_len, community,
			       aspath_len, aspath);
		}
	}
}

int main(int argc, char *argv[])
{
	int sockin, sockout, newsock;
	struct sockaddr_in serv_addr, sin, client_addr;
	int client_addr_len;
	fd_set fdr, fdw, fde;
	struct timeval tv;
	time_t select_wait, selectstart;
	int i, r;

	mask[0]=0;
	for (i=1; i<=32; i++)
		mask[i]=htonl(0xfffffffful<<(32-i));
	if (config(CONFNAME))
		exit(3);
	setstatus(IDLE);
	init_map(argc, argv);
	/* open listening socket */
	serv_addr.sin_port = bindport;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
	sockin=-1;

	while (1)
	{
		if (sockin==-1)
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
				sockin=-1;
			} else
				/* waiting for incoming connection */
				listen(sockin, 5);
		}

		setstatus(ACTIVE);
		/* try to connect */
		setstatus(CONNECT);
		if ((sockout = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		{	Log (0, "socket: %s", strerror(errno));
			exit(1);
		}
		sin.sin_addr.s_addr = remote;
		sin.sin_port = port;
		sin.sin_family = AF_INET;
		r = fcntl (sockout, F_GETFL, 0) ;
		if (r >= 0)
			r = fcntl (sockout, F_SETFL, r | O_NONBLOCK) ;
		if (connect(sockout, (struct sockaddr *)&sin, sizeof(sin)))
		{	
			if (errno != EINPROGRESS)
			{	Log(0, "Can't connect: %s", strerror(errno));
				close(sockout);
				sockout=-1;
				setstatus(ACTIVE);
			}
		}
		select_wait=waittime;
repselect:
		if (sockin==-1 && sockout==-1)
		{	sleep(select_wait);
			continue;
		}
		FD_ZERO(&fdr);
		FD_ZERO(&fdw);
		FD_ZERO(&fde);
		if (sockin!=-1)
			FD_SET(sockin, &fdr);
		if (sockout != -1)
		{	FD_SET(sockout, &fdw);
			FD_SET(sockout, &fde);
			setstatus(CONNECT);
		} else
			setstatus(ACTIVE);
		tv.tv_sec = select_wait;
		tv.tv_usec = 0;
		selectstart = time(NULL);
		r = select(((sockin>sockout) ? sockin : sockout)+1, &fdr, &fdw, &fde, &tv);
		if (r==-1)
		{	Log(0, "Select: %s", strerror(errno));
			setstatus(IDLE);
			sleep(select_wait-(selectstart-time(NULL)));
		} else if (r==0)
		{	Log(5, "Select: timeout");
			setstatus(IDLE);
		} else
		{	if (sockout!=-1 && FD_ISSET(sockout, &fde))
			{
				Log(5, "Select: connect() exception");
errconnect:
				close(sockout);
				sockout=-1;
				select_wait-=time(NULL)-selectstart;
				if (r==1 && select_wait>0) goto repselect;
			}
			if (sockout!=-1 && FD_ISSET(sockout, &fdw))
			{	int rr=0; i=sizeof(r);
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
				rr = fcntl (sockout, F_GETFL, 0) ;
				if (rr >= 0)
					rr = fcntl (sockout, F_SETFL, rr & ~O_NONBLOCK) ;
				if (sockin!=-1) close(sockin);
				sockin=-1;
				Log(4, "Outgoing bgp session");
				bgpsession(sockout);
				reset_table();
			}
			if (sockin!=-1 && FD_ISSET(sockin, &fdr))
			{	/* incoming connection */
				setstatus(CONNECT);
				if (sockout!=-1) close(sockout);
				sockout=-1;
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
						sockout=sockin=-1;
						Log(4, "Incoming bgp session");
						bgpsession(newsock);
						close(newsock);
						reset_table();
					}
				}
			}
		}
		if (sockout!=-1)
		{	close(sockout);
			sockout=-1;
		}
		setstatus(IDLE);
	}
}

