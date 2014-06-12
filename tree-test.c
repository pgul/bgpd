#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bgpd.h"

#define INP_ERROR { fprintf(stderr, "Input error in line %u\n", nline); continue; }

static int parse_aspath(uint32_t *aspath, int *aspath_len, char *str)
{
	char *p;

	*aspath_len = 0;
	while (str && *str) {
		p = strsep(&str, " ");
		if (*aspath_len >= 256)
			return -1;
		if (!isdigit(*p))
			return -1;
		aspath[(*aspath_len)++] = htonl(atoi(p));
	}
	return 0;
}

static int parse_community(uint32_t *community, int *comm_len, char *str)
{
	char *p;
	int comm1;

	*comm_len = 0;
	while (str && *str) {
		p = strsep(&str, ":");
		if (str == NULL) return -1;
		if (*comm_len >= 256)
			return -1;
		if (!isdigit(*p))
			return -1;
		comm1 = atoi(p);
		p = strsep(&str, " ");
		if (!isdigit(*p))
			return -1;
		community[(*comm_len)++] = (htons(atoi(p))<<16) | htons(comm1);
	}
	return 0;
}

static void check_tree(void)
{
}

int main(int argc, char *argv[])
{
	char *confname;
	char str[256];
	in_addr_t prefix, nexthop;
	int preflen, nline;

	confname = CONFNAME;
	if (argc > 1)
		confname = argv[1];
	if (config(confname))
		return 3;
	puts("Read updates from stdin");
	nline = 0;
	reset_table();
	do_initmap();
	perlbgpup();
	while (fgets(str, sizeof(str), stdin)) {
		int new = 1;
		char *p = str, *temps;

		nline++;
		if (*p == '-') {
			new = 0;
			p++;
		}
		prefix = inet_addr(strsep(&p, "/"));
		if (prefix == INADDR_NONE || p == NULL || !isdigit(*p))
			INP_ERROR;
		preflen = atoi(strsep(&p, " "));
		if (!new) {
			if (p) INP_ERROR;
			withdraw(prefix, preflen);
		} else {
			uint32_t aspath[256], community[256];
			int aspath_len, comm_len;

			if (p == NULL) INP_ERROR;
			nexthop = inet_addr(strsep(&p, " "));
			if (nexthop == INADDR_NONE) INP_ERROR;
			if (*p++ != '"') INP_ERROR;
			temps = strsep(&p, "\"");
			if (p == NULL) INP_ERROR;
			if (parse_aspath(aspath, &aspath_len, temps) != 0) {
				INP_ERROR;
			}
			if (*p == ' ') {
				p++;
				if (*p++ != '"') INP_ERROR;
				temps = strsep(&p, "\"");
				if (p == NULL) INP_ERROR;
				if (*p && *p != '\n') INP_ERROR;
				if (parse_community(community, &comm_len, temps) != 0) {
					INP_ERROR;
				}
			} else if (*p == '\0') {
				comm_len = 0;
			} else {
				INP_ERROR;
			}
			update(prefix, preflen, comm_len, community, aspath_len, aspath, nexthop);
		}
		check_tree();
	}
	puts("Test passed");
	return 0;
}

