#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "bgpd.h"

ushort my_as, remote_as;
ulong router_id, remote;
ushort bindport, port;
time_t waittime;
ushort holdtime;
int ballance_cnt, maxdepth;
ulong mapkey;
char perlfile[256], plsetclass[256];

int config(char *confname)
{
	FILE *f;
	char str[256], *p, *pp;
	struct servent *entry;

	bindport = port = htons(179);
	waittime = 60;
	holdtime = 180;
	ballance_cnt = 1000;
	maxdepth = 50;
	mapkey = *(ulong *)"gul@";
	my_as = remote_as = 0;
	router_id = remote = (ulong)-1;
	strcpy(perlfile, "bgpd.pl");
	strcpy(plsetclass, "setclass");
	f = fopen(confname, "r");
	if (f == NULL)
	{	Log(0, "Can't open %s: %s", confname, strerror(errno));
		return 1;
	}
	while (fgets(str, sizeof(str), f))
	{
		p=strchr(str, '\n');
		if (p) *p='\0';
		p=strchr(str, '#');
		if (p) *p='\0';
		for (p=str; *p && isspace(*p); p++);
		if (p!=str) strcpy(str, p);
		if (*p=='\0') continue;
		for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
		p=strchr(str, '=');
		if (p==NULL)
		{	Log(1, "Unknown line in config: '%s'", str);
			continue;
		}
		*p++='\0';
		while (*p & isspace(*p)) p++;
		if (*str == '\0')
		{	str[strlen(str)]='=';
			Log(1, "Unknown line in config: '%s'", str);
			continue;
		}
		for (pp=str+strlen(str)-1; isspace(*p); *p--='\0');
		if (strcasecmp(str, "my-as")==0)
		{	my_as = atoi(p);
			if (!isdigit(*p) || my_as<=0)
			{	Log(0, "Incorrect my-as=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "remote-as")==0)
		{	remote_as = atoi(p);
			if (!isdigit(*p) || remote_as<=0)
			{	Log(0, "Incorrect remote-as=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "router-id")==0)
		{	router_id = inet_addr(p);
			if (router_id == (ulong)-1)
			{	Log(0, "Incorrect router-id=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "remote")==0)
		{	remote = inet_addr(p);
			if (remote == (ulong)-1)
			{	Log(0, "Incorrect remote=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "bindport")==0)
		{	entry = getservbyname(p, "tcp");
			if (entry)
			{	bindport = entry->s_port;
			} else if (isdigit(*(p)))
			{	bindport = htons((ushort)atoi(p));
			} else
			{	Log(1, "Unknown bindport=%s ignored", p);
			}
			continue;
		}
		if (strcasecmp(str, "port")==0)
		{	entry = getservbyname(p, "tcp");
			if (entry)
			{	port = entry->s_port;
			} else if (isdigit(*(p)))
			{	port = htons((ushort)atoi(p));
			} else
			{	Log(1, "Unknown port=%s ignored", p);
			}
			continue;
		}
		if (strcasecmp(str, "waittime")==0)
		{	waittime = atoi(p);
			if (!isdigit(*p) || waittime<=0)
			{	Log(0, "Incorrect waittime=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "holdtime")==0)
		{	holdtime = atoi(p);
			if (!isdigit(*p) || holdtime<=0)
			{	Log(0, "Incorrect holdtime=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "ballance-check")==0)
		{	ballance_cnt = atoi(p);
			if (!isdigit(*p) || ballance_cnt<=0)
			{	Log(0, "Incorrect ballance-check=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "maxdepth")==0)
		{	maxdepth = atoi(p);
			if (!isdigit(*p) || maxdepth<=0)
			{	Log(0, "Incorrect maxdepth=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "mapkey")==0)
		{	mapkey = atoi(p);
			if (!isdigit(*p) || mapkey<=0)
			{	Log(0, "Incorrect mapkey=%s in config!", p);
				return 1;
			}
			continue;
		}
		if (strcasecmp(str, "setclass")==0)
		{	strcpy(str, p);
			p=strstr(str, "::");
			if (p==NULL)
			{	Log(0, "Incorrect setclass=%s ignored!", str);
				continue;
			}
			*p=0;
			strncpy(perlfile, str, sizeof(perlfile));
			strncpy(plsetclass, p+2, sizeof(plsetclass));
			continue;
		}

		Log(6, "Unknown keyword %s in config ignored", str);
        }
	fclose(f);
	if (my_as==0)
	{	Log(0, "my-as not specified!");
		return 1;
	}
	if (remote_as==0)
	{	Log(0, "remote-as not specified!");
		return 1;
	}
	if (router_id == (ulong)-1)
	{	Log(0, "router-id not specified!");
		return 1;
	}
	if (remote == (ulong)-1)
	{	Log(0, "remote not specified!");
		return 1;
	}
	return 0;
}
