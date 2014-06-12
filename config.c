#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "bgpd.h"
#include "ipmap.h"

uint32_t my_as, remote_as;
uint32_t router_id;
in_addr_t remote;
uint16_t bindport, port;
time_t waittime, reconnect_time;
uint16_t holdtime;
int balance_cnt, maxdepth;
unsigned long int mapkey;
char perlfile[256], plsetclass[256], plinitmap[256], plbgpup[256], plbgpdown[256];
char plfilter[256], plupdate[256], plwithdraw[256], plupdatedone[256], plkeepalive[256];
char pidfile[256] = PIDFILE;

int config(char *confname)
{
	FILE *f;
	char str[256], *p, *pp;
	struct servent *entry;

	bindport = port = htons(179);
	waittime = 60;
	reconnect_time = 10;
	holdtime = 180;
	balance_cnt = 1000;
	maxdepth = 50;
	mapkey = MAPKEY;
	my_as = remote_as = 0;
	router_id = (uint32_t)-1;
	remote = INADDR_NONE;
	strcpy(perlfile, "bgpd.pl");
	strcpy(plsetclass, "setclass");
	strcpy(plinitmap, "initmap");
	strcpy(plbgpup, "bgpup");
	strcpy(plbgpdown, "bgpdown");
	strcpy(plfilter, "filter");
	strcpy(plupdate, "update");
	strcpy(plwithdraw, "withdraw");
	strcpy(plupdatedone, "update_done");
	strcpy(plkeepalive, "keepalive");
	f = fopen(confname, "r");
	if (f == NULL)
	{	Log(0, "Can't open %s: %s", confname, strerror(errno));
		return 1;
	}
	while (fgets(str, sizeof(str), f))
	{
		p=strchr(str, '\n');
		if (p) *p = '\0';
		p = strchr(str, '#');
		if (p) *p = '\0';
		for (p = str; *p && isspace(*p); p++);
		if (p != str) strcpy(str, p);
		if (*p == '\0') continue;
		for (p = str + strlen(str) - 1; isspace(*p); *p-- = '\0');
		p = strchr(str, '=');
		if (p == NULL)
		{	Log(1, "Unknown line in config: '%s'", str);
			continue;
		}
		*p++ = '\0';
		while (*p & isspace(*p)) p++;
		if (*str == '\0')
		{	str[strlen(str)] = '=';
			Log(1, "Unknown line in config: '%s'", str);
			continue;
		}
		for (pp = str + strlen(str) - 1; isspace(*p); *p-- = '\0');
		if (strcasecmp(str, "my-as") == 0)
		{	my_as = atoi(p);
			if (!isdigit(*p) || my_as <= 0)
			{	Log(0, "Incorrect my-as=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "remote-as") == 0)
		{	remote_as = atoi(p);
			if (!isdigit(*p) || remote_as <= 0)
			{	Log(0, "Incorrect remote-as=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "router-id") == 0)
		{	router_id = inet_addr(p);
			if (router_id == (uint32_t)-1)
			{	Log(0, "Incorrect router-id=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "remote") == 0)
		{	remote = inet_addr(p);
			if (remote == INADDR_NONE)
			{	Log(0, "Incorrect remote=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "bindport") == 0)
		{	entry = getservbyname(p, "tcp");
			if (entry)
			{	bindport = entry->s_port;
			} else if (isdigit(*(p)))
			{	bindport = htons((uint16_t)atoi(p));
			} else
			{	Log(1, "Unknown bindport=%s ignored", p);
			}
			continue;
		}
		if (strcasecmp(str, "port") == 0)
		{	entry = getservbyname(p, "tcp");
			if (entry)
			{	port = entry->s_port;
			} else if (isdigit(*(p)))
			{	port = htons((uint16_t)atoi(p));
			} else
			{	Log(1, "Unknown port=%s ignored", p);
			}
			continue;
		}
		if (strcasecmp(str, "waittime") == 0)
		{	waittime = atoi(p);
			if (!isdigit(*p) || waittime <= 0)
			{	Log(0, "Incorrect waittime=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "holdtime") == 0)
		{	holdtime = atoi(p);
			if (!isdigit(*p) || holdtime <= 0)
			{	Log(0, "Incorrect holdtime=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "reconnect-time") == 0)
		{	reconnect_time = atoi(p);
			if (!isdigit(*p) || reconnect_time <= 0)
			{	Log(0, "Incorrect reconnect-time=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "balance-check") == 0)
		{	balance_cnt = atoi(p);
			if (!isdigit(*p) || balance_cnt <= 0)
			{	Log(0, "Incorrect balance-check=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "maxdepth") == 0)
		{	maxdepth = atoi(p);
			if (!isdigit(*p) || maxdepth <= 0)
			{	Log(0, "Incorrect maxdepth=%s in config!", p);
				return 1;
			}
			continue;
		}
#if NBITS>0
		if (strcasecmp(str, "mapkey") == 0)
		{	mapkey = atoi(p);
			if (!isdigit(*p) || mapkey <= 0)
			{	Log(0, "Incorrect mapkey=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "setclass") == 0)
		{	strcpy(str, p);
			p=strstr(str, "::");
			if (p)
			{	
				*p = 0;
				strncpy(perlfile, str, sizeof(perlfile));
				p += 2;
			}
			strncpy(plsetclass, p, sizeof(plsetclass));
			continue;
		}
#endif
		if (strcasecmp(str, "perlfile") == 0)
		{	strncpy(perlfile, p, sizeof(perlfile));
			continue;
		}
		if (strcasecmp(str, "pidfile") == 0)
		{	strncpy(pidfile, p, sizeof(pidfile));
			continue;
		}

		Log(6, "Unknown keyword %s in config ignored", str);
        }
	fclose(f);
	if (my_as == 0)
	{	Log(0, "my-as not specified!");
		return 1;
	}
	if (remote_as == 0)
	{	Log(0, "remote-as not specified!");
		return 1;
	}
	if (router_id == (uint32_t)-1)
	{	Log(0, "router-id not specified!");
		return 1;
	}
	if (remote == INADDR_NONE)
	{	Log(0, "remote not specified!");
		return 1;
	}
	return 0;
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

