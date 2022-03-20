#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/shm.h>
//#include <linux/shm.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif

#include "bgpd.h"
#include "ipmap.h"

#ifndef pTHX_
#define pTHX_
#endif
#ifndef pTHX
#define pTHX
#endif

struct route_obj
{
	uint32_t ip;
	char prefix_len;
	class_type class;
	struct route_obj *left, *right, *parent;
#ifdef SOFT_RECONFIG
	uint32_t nexthop;
	unsigned char aspath_len;
	unsigned char community_len;
	unsigned char disabled;
	uint32_t aspath[256]; /* will not be allocated fully */
	uint32_t community[256]; /* place holder, actually stored after aspath */
	/* then community */
#endif
};

#ifdef SOFT_RECONFIG
#define sizeofroute(r)	(sizeof(r) - sizeof((r).aspath) - sizeof((r).community) + (r).aspath_len * sizeof((r).aspath[0]) + (r).community_len * sizeof((r).community[0]))
#else
#define sizeofroute(r)	sizeof(r)
#endif

static struct route_obj *route_root = NULL;
class_type *map;
static int last_balanced = 0;
static int prefix_cnt, passive_cnt;
int mapinited;

static PerlInterpreter *perl = NULL;

static struct route_obj *findroute(struct route_obj *new, int addnew, int *added);
#if NBITS > 0
static void mapsetclass(uint32_t from, uint32_t to, class_type class);
static int  chclass(struct route_obj *obj);
#endif
static int  perlfilter(uint32_t prefix, int prefix_len,
           int community_len, uint32_t *community, int aspath_len, uint32_t *aspath, uint32_t nexthop);
static void perlupdate(uint32_t prefix, int prefix_len, int community_len,
           uint32_t *community, int aspath_len, uint32_t *aspath, uint32_t nexthop, int added);
static void perlwithdraw(uint32_t prefix, int prefix_len);
static void perlupdate_done(void);
static void perlkeepalive(int sent);

void boot_DynaLoader(pTHX_ CV *cv);

#if NBITS > 0
static XS(perl_initclass)
{
	dXSARGS;
	char *ip;
	STRLEN n_a;
	char *p;
	int preflen=24, class, added;
	struct route_obj r, *pr;

	if (items != 2)
	{	Log(0, "Wrong params number to setclass (need 2, exist %d)", items);
	XSRETURN_EMPTY;
	}
	ip = (char *)SvPV(ST(0), n_a); if (n_a == 0) ip = "";
	ip = strdup(ip);
	class = SvIV(ST(1));
	p = strchr(ip, '/');
	if (p)
	{	*p++ = '\0';
		preflen = atoi(p);
	}
	memset(&r, 0, sizeof(r));
	r.class = (class_type)class;
	r.ip = ntohl(inet_addr(ip));
	r.prefix_len = (char)preflen;
	pr = findroute(&r, 1, &added);
	if (!pr)
	{	Log(0, "Internal error!");
		free(ip);
		exit(2);
	}
	if (!added && pr->class == r.class)
		return;
	if (!added) pr->class = r.class;
	chclass(pr);
	Log(6, "Initclass %s/%u to %u", ip, preflen, class);
	free(ip);

	XSRETURN_EMPTY;
}
#endif

static void xs_init(pTHX)
{
	static char *file = __FILE__;
	dXSUB_SYS;
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
#if NBITS > 0
	newXS("initclass",  perl_initclass,  file);
#endif
}

static void exitperl(void)
{
	if (perl)
	{
		perl_destruct(perl);
		perl_free(perl);
#ifdef PERL_SYS_TERM
		PERL_SYS_TERM();
#endif
		perl = NULL;
	}
}

static int PerlStart(void)
{
	int rc;
	char *perlargs[] = {"", "", NULL};
	char **perlargv = perlargs;
	int perlargc = 2;
	SV *svremote, *svremoteas;

	perlargs[1] = perlfile;
	if (access(perlfile, R_OK))
	{	Log(0, "Can't read %s: %s", perlfile, strerror(errno));
		return 1;
	}
#ifdef PERL_SYS_INIT3
	PERL_SYS_INIT3(&perlargc, &perlargv, NULL);
#endif
	perl = perl_alloc();
	perl_construct(perl);
	rc = perl_parse(perl, xs_init, perlargc, perlargv, NULL);
	if (rc)
	{	Log(0, "Can't parse %s", perlfile);
		perl_destruct(perl);
		perl_free(perl);
		perl = NULL;
		return 1;
	}
	atexit(exitperl);
	svremote   = perl_get_sv("remote", TRUE);
	svremoteas = perl_get_sv("remote_as", TRUE);
	SvREADONLY_off(svremote);
	SvREADONLY_off(svremoteas);
	sv_setpv(svremote, inet_ntoa(*(struct in_addr *)&remote));
	sv_setiv(svremoteas, remote_as);
	SvREADONLY_on(svremote);
	SvREADONLY_on(svremoteas);
	return 0;
}

static void perlinitmap(void)
{
	STRLEN n_a;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plinitmap, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plinitmap, SvPV(ERRSV, n_a));
		exit(4);
	} else
		Log(2, "Perl %s() success", plinitmap);
}

void perlbgpup(void)
{
	STRLEN n_a;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plbgpup, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plbgpup, SvPV(ERRSV, n_a));
		exit(4);
	} else
		Log(2, "Perl %s() success", plbgpup);
}

void perlbgpdown(void)
{
	STRLEN n_a;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plbgpdown, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plbgpdown, SvPV(ERRSV, n_a));
		exit(4);
	} else
		Log(2, "Perl %s() success", plbgpdown);
}

#if NBITS > 0
static class_type perlsetclass(char *community, char *aspath, char *prefix)
{
	char *prc;
	SV *svcommunity, *svaspath, *svprefix, *svret;
	STRLEN n_a;
	class_type class;

	dSP;
	svcommunity = perl_get_sv("community", TRUE);
	svaspath    = perl_get_sv("aspath", TRUE);
	svprefix    = perl_get_sv("prefix", TRUE);
	SvREADONLY_off(svcommunity);
	SvREADONLY_off(svaspath);
	SvREADONLY_off(svprefix);
	sv_setpv(svcommunity, community);
	sv_setpv(svaspath, aspath);
	sv_setpv(svprefix, prefix);
	SvREADONLY_on(svcommunity);
	SvREADONLY_on(svaspath);
	SvREADONLY_on(svprefix);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plsetclass, G_EVAL|G_SCALAR);
	SPAGAIN;
	svret=POPs;
	if (SvTRUE(svret))
		prc = strdup(SvPV(svret, n_a));
	else
		prc = NULL;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plsetclass, SvPV(ERRSV, n_a));
		exit(4);
	}
	if (n_a == 0 && prc)
	{
		free(prc);
		prc = NULL;
	}
	if (prc)
	{ 
		class = (class_type)atoi(prc);
		free(prc);
	} else
	{
		class = 0;
	}
	return class;
}
#endif

static void communitystr(int comm_len, uint32_t *community, char *scomm, int len)
{
	char *p;
	uint16_t firstas, secondas;
	int i;

	p = scomm;
	*p = '\0';
	for (i = 0; i < comm_len; i++)
	{	if (*scomm) *p++ = ' ';
		firstas = ntohs(*(uint16_t *)(community + i));
		secondas = ntohs(((uint16_t *)(community + i))[1]);
		if (firstas == 0xffff && secondas == 0xff01)
			strcpy(p, "no-export");
		else if (firstas == 0xffff && secondas == 0xff02)
			strcpy(p, "no-advertise");
		else if (firstas == 0xffff && secondas == 0xff03)
			strcpy(p, "no-export-subconfed");
		else
			sprintf(p, "%u:%u", firstas, secondas);
		p += strlen(p);
		if (p - scomm + 22 > len)
			break;
	}
}

static void aspathstr(int aspath_len, uint32_t *aspath, char *saspath, int len)
{
	char *p;
	int i;

	saspath[0] = '\0';
	p = saspath;
	for (i = 0; i < aspath_len; i++)
	{	if (*saspath) *p++ = ' ';
		sprintf(p, "%u", ntohl(aspath[i]));
		p += strlen(p);
		if (p - saspath + 15 > len)
			break;
	}
}

#if NBITS > 0
static class_type setclass(uint32_t *community, int community_len,
                           uint32_t *aspath, int aspath_len,
                           uint32_t prefix, int prefix_len)
{
	char saspath[256], scommunity[256], sprefix[32];

	aspathstr(aspath_len, aspath, saspath, sizeof(saspath));
	communitystr(community_len, community, scommunity, sizeof(scommunity));
	snprintf(sprefix, sizeof(sprefix), "%s/%u", inet_ntoa(*((struct in_addr *)&prefix)), prefix_len);
	return perlsetclass(scommunity, saspath, sprefix);
}
#endif

static int compare(struct route_obj *a, struct route_obj *b)
{
	if (a->ip > b->ip) return 1;
	if (a->ip < b->ip) return -1;
	if (a->prefix_len > b->prefix_len) return 1;
	if (a->prefix_len < b->prefix_len) return -1;
	return 0;
}

#ifdef SOFT_RECONFIG
/* including disabled */
static struct route_obj *firstroute(struct route_obj *root)
{
	while (root->left)
		root = root->left;
	return root;
}
#endif

/* including disabled */
static struct route_obj *nextroute(struct route_obj *cur)
{
	struct route_obj *newcur;

	if (!cur) return NULL;
	if (!cur->right)
	{	while (cur->parent)
		{	newcur = cur->parent;
			if (newcur->right != cur)
				return newcur;
			cur = newcur;
		}
		return NULL;
	}
	for (cur = cur->right; cur->left; cur = cur->left);
	return cur;
}

static int routecnt(struct route_obj *root)
{
	struct route_obj *r, *p;
	int cnt;

	if (root == NULL) return 0;
	r = root;
	cnt = 0;
	while (1)
	{	if (r->left)
		{	r = r->left;
			continue;
		}
		cnt++;
		if (r->right)
		{	r = r->right;
			continue;
		}
		if (r == root)
			return cnt;
		while (1)
		{	p = r->parent;
			if (r == p->right)
			{	r = p;
				if (r == root)
					return cnt;
				continue;
			}
			r = p;
			cnt++;
			if (r->right)
			{	r = r->right;
				break;
			}
			if (r == root)
				return cnt;
		}
	}	
}

static int routedepth(struct route_obj *root)
{
	struct route_obj *r, *p;
	int maxdepth, curdepth;

	if (root == NULL) return 0;
	r = root;
	maxdepth = curdepth = 0;
	while (1)
	{	if (r->left)
		{	r = r->left;
			if (++curdepth > maxdepth) maxdepth = curdepth;
			continue;
		}
		if (r->right)
		{	r = r->right;
			if (++curdepth > maxdepth) maxdepth = curdepth;
			continue;
		}
		if (r == root)
			return maxdepth;
		while (1)
		{	p = r->parent;
			if (r == p->right)
			{	r = p;
				curdepth--;
				if (r == root)
					return maxdepth;
				continue;
			}
			r = p;
			curdepth--;
			if (r->right)
			{	r = r->right;
				curdepth++;
				break;
			}
			if (r == root)
				return maxdepth;
		}
	}	
}


static struct route_obj *balance(struct route_obj *r)
{
	int cnt_left, cnt_right, i;
	struct route_obj *p, *pp;

	while (1)
	{
		cnt_left = routecnt(r->left);
		cnt_right = routecnt(r->right);
		if ((cnt_left + 1) * 2 < cnt_right)
		{	/* make r->right as root */
			p = r->right;
			r->right = NULL;
		} else if ((cnt_right + 1) * 2 < cnt_left)
		{	/* make r->left as root */
			p = r->left;
			r->left = NULL;
		} else
			return r;
		p->parent = r->parent;
		if (r->parent)
		{	if (r->parent->left == r)
				r->parent->left = p;
			else
				r->parent->right = p;
		} else
			route_root = p;
		r->parent = NULL;
		/* add r to the tree */
		pp = findroute(r, 2, &i);
		if (pp == NULL || i == 0 || pp != r)
		{	Log(0, "Internal error!");
			exit(2);
		}
		r = p;
		last_balanced = 0;
	}
}

static void balance_tree(void)
{
	struct route_obj *r, *p;
	int depth;

	last_balanced = 0;
	r = route_root;
	if (r == NULL) return;
	depth = routedepth(route_root);
	if (depth < maxdepth)
	{	Log(6, "Binary tree balancing not needed (depth %u)", depth);
		return;
	}
	Log(5, "Binary tree balancing (depth %u)...", depth);
	while (1)
	{	r = balance(r);
		if (r->left)
		{	r = r->left;
			continue;
		}
		if (r->right)
		{	r = r->right;
			continue;
		}
		while (1)
		{	p = r->parent;
			if (p == NULL)
			{	depth = routedepth(route_root);
				Log(5, "Ballancing done, depth %u", depth);
				if (depth > maxdepth)
				{	maxdepth = depth + 1;
					Log(1, "maxdepth too small, changed to %u", maxdepth);
				}
				return;
			}
			if (r == p->right || p->right == NULL)
			{	r = p;
				continue;
			}
			r = p->right;
			break;
		}
	}
}

/* addnew = 0  - return NULL if not found */
/* addnew = -1 - return nearest bigger (incl disabled) if not found */
/* addnew = 1  - create new node and add to tree if not found */
/* addnew > 1  - add "new" to the tree, do not clone */
static struct route_obj *findroute(struct route_obj *new, int addnew, int *added)
{
	struct route_obj *cur, *p, **newcur;
	int i;

	if (added) *added = 0;
	for (cur = route_root; ; cur = *newcur)
	{	if (cur == NULL)
		{	newcur = &route_root;
		} else
		{	i = compare(new, cur);
			if (i == 0) return cur;
			if (i > 0) newcur = &cur->right;
			else newcur = &cur->left;
		}
		if (*newcur == NULL)
		{	if (addnew == 0) return NULL;
			if (addnew == -1) /* find nearest bigger */
			{	if (newcur == &cur->right)
					return nextroute(cur);
				else
					return cur;
			}
			if (addnew == 1)
			{	p = malloc(sizeofroute(*new));
				if (p == NULL)
				{	Log(0, "Memory allocation fail!");
					exit(1);
				}
				memcpy(p, new, sizeofroute(*new));
				if (p->right) p->right->parent = p;
				if (p->left) p->left->parent = p;
				prefix_cnt++;
#ifdef SOFT_RECONFIG
				if (p->disabled) passive_cnt++;
#endif
			} else
				p = new;
			p->parent = cur;
			*newcur = p;
			if (added) *added=1;
			if (addnew == 1 && balance_cnt && last_balanced++ >= balance_cnt)
				balance_tree();
			return p;
		}
	}
}

#if NBITS > 0
static struct route_obj *aggregate_route(struct route_obj *cur)
{
	struct route_obj aggregate, *p;

	memset(&aggregate, 0, sizeof(aggregate));
	aggregate.ip = cur->ip; aggregate.prefix_len = cur->prefix_len;
	while (aggregate.prefix_len)
	{	aggregate.prefix_len--;
		aggregate.ip &= 0xfffffffful << (32 - (int)aggregate.prefix_len);
		if ((p = findroute(&aggregate, 0, NULL)) != NULL)
#ifdef SOFT_RECONFIG
			if (!p->disabled)
#endif
				return p;
	}
	return NULL;
}
#endif

static void delroute(struct route_obj *route)
{
	if (!route->left)
	{	if (route->parent)
		{	if (route->parent->right == route)
				route->parent->right = route->right;
			else
				route->parent->left = route->right;
		} else
			route_root = route->right;
		if (route->right)
			route->right->parent = route->parent;
	} else
	{
		if (route->parent)
		{	if (route->parent->right == route)
				route->parent->right = route->left;
			else
				route->parent->left = route->left;
		} else
			route_root = route->left;
		route->left->parent = route->parent;
		if (route->right)
		{	// add the route object with all its subtree
			if (findroute(route->right, 2, NULL) != route->right)
			{	Log(0, "Internal error in delroute!");
				exit(3);
			}
		}
	}
#ifdef SOFT_RECONFIG
	if (route->disabled) passive_cnt--;
#endif
	prefix_cnt--;
	free(route);
	if (balance_cnt && last_balanced++ >= balance_cnt)
		balance_tree();
}

#if NBITS > 0
#if NBITS <= 8
static void shmemset(class_type *map, int offs, char class, unsigned int size)
{
	memset(&map[offs], class, size * sizeof(class_type));
}

static class_type shmgetone(class_type *map, unsigned int offs)
{
	return map[offs];
}
#endif

static void shmputone(class_type *map, unsigned int offs, class_type class)
{
	map[offs] = class;
}

static void mapsetclass(uint32_t from, uint32_t to, class_type class)
{
#if MAXPREFIX < 32
	from >>= (32 - MAXPREFIX);
	if (to + 1 == 0)
		to = 0x80000000ul >> (31 - MAXPREFIX);
	else
		to = (to + 1) >> (32 - MAXPREFIX);
	if (from == to)
		return;
#else // MAXPREFIX == 32
	to++;
#endif // MAXPREFIX == 32
#if NBITS == 16
	{	int i;
		i = from;
		do
		{	shmputone(map, i, class);
		} while (++i != to);
	}
#elif NBITS == 8
#if MAXPREFIX == 32
	if (from == 0 && to == 0)
	{	shmemset(map, 0, class, 0x80000000u);
		shmemset(map, 0x80000000u, class, 0x80000000);
	} else
#endif // MAXPREFIX == 32
	shmemset(map, from, class, to-from);
#else // NBITS < 8
	{	uint32_t firstbyte, lastbyte;
		char mask1, mask2;
		firstbyte = from / (8 / NBITS);
		lastbyte = (to - 1) / (8 / NBITS);
		mask1 = (0xff << ((from - firstbyte * (8 / NBITS)) * NBITS)) & 0xff;
		mask2 = 0xff >> (8 - ((to - lastbyte * (8 / NBITS))) * NBITS);
#if NBITS == 1
		class = (class ? 0xff : 0);
#elif NBITS == 2
		class |= (class << 2) | (class << 4) | (class << 6);
#else // NBITS == 4
		class |= class << 4;
#endif
		if (firstbyte == lastbyte)
		{	mask1 &= mask2;
			shmputone(map, firstbyte, (shmgetone(map, firstbyte) & ~mask1) | (class & mask1));
			// map[firstbyte] = (map[firstbyte] & ~mask1) | (class & mask1);
			return;
		}
		if (mask1 != 0xff)
		{
			shmputone(map, firstbyte, (shmgetone(map, firstbyte) & ~mask1) | (class & mask1));
			// map[firstbyte] = (map[firstbyte] & ~mask1) | (class & mask1);
			firstbyte++;
		}
		if (mask2 != 0xff)
		{
			shmputone(map, lastbyte, (shmgetone(map, lastbyte) & ~mask2) | (class & mask2));
			// map[lastbyte] = (map[lastbyte] & ~mask2) | (class & mask2);
			lastbyte--;
		}
		if (firstbyte <= lastbyte)
			shmemset(map, firstbyte, class, lastbyte - firstbyte + 1);
	}
#endif // NBITS
}

static int chclass(struct route_obj *obj)
{
	struct route_obj *r;
	uint32_t first_ip, last_ip;

	r = obj;	/* for obj->class */
	first_ip = r->ip;
	last_ip = first_ip + (0xfffffffful >> (int)r->prefix_len);
	for (;;)
	{
#ifdef SOFT_RECONFIG
		do
		{
			r = nextroute(r);
		} while (r && r->disabled);
#else
		r = nextroute(r);
#endif
		if (r == NULL || r->ip > last_ip)
		{	mapsetclass(first_ip, last_ip, obj->class);
			return 0;
		}
		if (r->ip < first_ip) continue;
		if (first_ip != r->ip)
			mapsetclass(first_ip, r->ip - 1, obj->class);
		first_ip = r->ip + (0xfffffffful >> (int)r->prefix_len) + 1;
		if (first_ip == 0 || first_ip > last_ip) return 0;
	}
}
#endif

void withdraw(uint32_t prefix, int prefix_len)
{
	struct route_obj r, *p;
#ifndef SOFT_RECONFIG
	int enabled;
#endif
#if NBITS > 0
	struct route_obj *pp;
	class_type cl;
#endif

#ifndef SOFT_RECONFIG
	enabled = perlfilter(prefix, prefix_len, 0, NULL, 0, NULL, 0);
#endif
	r.ip = ntohl(prefix); r.prefix_len = (char)prefix_len;
	p = findroute(&r, 0, NULL);
	if (p == NULL)
	{
#ifndef SOFT_RECONFIG
		if (enabled)
#endif
			Log(0, "Can't withdraw unexistant route %s/%u",
			    inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
		return;
	}
#ifdef SOFT_RECONFIG
	if (!p->disabled)
#endif
	{
		perlwithdraw(prefix, prefix_len);
#if NBITS > 0
		/* find aggregate route */
		pp = aggregate_route(p);
		cl = (pp == NULL ? 0 : pp->class);
		/* modify classes */
		if (p->class != cl)
		{	p->class = cl;
			chclass(p);
		}
#endif
		Log(2, "Withdraw route %s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
	}
	/* remove route */
	delroute(p);
}

void update(uint32_t prefix, int prefix_len, int community_len, uint32_t *community,
            int aspath_len, uint32_t *aspath, uint32_t nexthop)
{
	struct route_obj r, *p;
	int added;
	int enabled;

	enabled = perlfilter(prefix, prefix_len, community_len, community, aspath_len, aspath, nexthop);
	memset(&r, 0, sizeof(r));
	if (!enabled)
	{
		Log(2, "Filtered route %s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
#ifdef SOFT_RECONFIG
		r.disabled = 1;
#endif
	}
#if NBITS > 0
	if (enabled)
		r.class = setclass(community, community_len, aspath, aspath_len, prefix, prefix_len);
#endif
	r.ip = ntohl(prefix);
	r.prefix_len = (char)prefix_len;
#ifdef SOFT_RECONFIG
	r.nexthop = nexthop;
	r.aspath_len = (unsigned char)aspath_len;
	memcpy(r.aspath, aspath, sizeof(*r.aspath) * r.aspath_len);
	r.community_len = (unsigned char)community_len;
	memcpy(r.aspath + r.aspath_len, community, sizeof(*r.community) * r.community_len);

	p = findroute(&r, 1, &added);
	if (!p)
	{	Log(0, "Internal error!");
		exit(2);
	}
#else
	p = findroute(&r, enabled ? 1 : 0, &added);
	if (!p)
	{
		if (!enabled) return;
		Log(0, "Internal error!");
		exit(2);
	}
#endif
	if (!enabled)
	{
		if (!added)
		{
#ifdef SOFT_RECONFIG
			if (!p->disabled)
#endif
			{
				/* filtered out existing route */
				/* perform withdraw procedure */
#if NBITS>0
				struct route_obj *pp;
				class_type cl;
#endif

				perlwithdraw(prefix, prefix_len);
#if NBITS > 0
				/* find aggregate route */
				pp = aggregate_route(p);
				cl = (pp == NULL ? 0 : pp->class);
				/* modify classes */
				if (p->class != cl)
				{	p->class = cl;
					chclass(p);
				}
#endif
				Log(2, "Remove route %s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
#ifdef SOFT_RECONFIG
				passive_cnt++;
#else
				delroute(p);
				return;
#endif
			}
		}
	}
	else
	{	/* enabled */
		perlupdate(prefix, prefix_len, community_len, community, aspath_len, aspath, nexthop, added);
#if NBITS == 0
		Log(2, "Updated %sroute %s/%u",
		    (added ? "" : "existing "),
		    inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
#else
		Log(2, "Updated %sroute %s/%u, class %u",
		    (added ? "" : "existing "),
		    inet_ntoa(*(struct in_addr *)&prefix), prefix_len, r.class);
		if (added || p->class != r.class)
		{
			if (!added) p->class = r.class;
			chclass(p);
		}
#endif
#ifdef SOFT_RECONFIG
		if (!added && p->disabled)
			passive_cnt--;
#endif
	}
#ifdef SOFT_RECONFIG
	if (added) return;
	r.parent = p->parent;
	r.left = p->left;
	r.right = p->right;
	if (sizeofroute(*p) == sizeofroute(r))
		memcpy(p, &r, sizeofroute(r));
	else
	{
		struct route_obj *upd_route;

		upd_route = malloc(sizeofroute(r));
		memcpy(upd_route, &r, sizeofroute(r));
		if (r.parent && r.parent->left == p)
			r.parent->left = upd_route;
		if (r.parent && r.parent->right == p)
			r.parent->right = upd_route;
		if (r.left)
			r.left->parent = upd_route;
		if (r.right)
			r.right->parent = upd_route;
		if (route_root == p)
			route_root = upd_route;
		free(p);
	}
#endif
}

void update_done(void)
{
	perlupdate_done();
}

void reset_table(void)
{
	struct route_obj *cur = route_root, *p;

	if (route_root == NULL) return;
	while (cur)
	{	if (cur->left)
			cur = cur->left;
		else if (cur->right)
			cur = cur->right;
		else
		{	p = cur->parent;
			free(cur);
			if (p == NULL) break;
			if (p->left == cur)
				p->left=NULL;
			else
				p->right=NULL;
			cur=p;
		}
	}
	route_root = NULL;
	last_balanced = 0;
	prefix_cnt = passive_cnt = 0;
	perlbgpdown();
	Log(2, "BGP table cleared");
}

void do_initmap(void)
{
	if (mapinited) return;
#if NBITS > 0
	mapsetclass(0, 0xfffffffful, 0);
#endif
	exitperl();
	PerlStart();
	if (perl == NULL)
		exit(4);
	Log(2, "Perl loaded");
	perlinitmap();
	mapinited = 1;
}

void keepalive(int sent)
{
	Log(5, "KeepAlive %s, total %u prefixes", (sent ? "sent" : "received"), prefix_cnt);
#ifdef SOFT_RECONFIG
	Log(5, "%u passive prefixes", passive_cnt);
#endif
	perlkeepalive(sent);
}

#if NBITS > 0
static int shmid = -1;

static void freeshmem(void)
{
	struct shmid_ds buf;
	if (map)
	{	shmdt(map);
		map = NULL;
	}
	if (shmid != -1)
		if (shmctl(shmid, IPC_STAT, &buf) == 0)
			if (buf.shm_nattch == 0)
				shmctl(shmid, IPC_RMID, &buf);
}
#endif

void init_map(int argc, char *argv[])
{
#if NBITS > 0
	key_t k;
	int created = 0;

	if (argc > 1 && isdigit(argv[1][0]))
		k = atol(argv[1]);
	else
		k = mapkey;
	atexit(freeshmem);
shmagain:
	shmid = shmget(k, MAPSIZE, 0600);
	if (shmid == -1)
	{
		if (errno != ENOENT)
		{	Log(0, "Can't get shared memory (key %u, size %u): %s!", k, MAPSIZE, strerror(errno));
			exit(1);
		}
		shmid = shmget(k, MAPSIZE, IPC_CREAT|IPC_EXCL|0600);
		if (shmid == -1)
		{	if (errno != EEXIST)
			{	Log(0, "Can't allocate %u bytes of shared memory: %s!", MAPSIZE, strerror(errno));
				exit(1);
			}
			sleep(1);
			goto shmagain;
		}
		Log(5, "Shared memory segment created");
		created=1;
	} else
		Log(5, "Shared memory segment attached");
	map = shmat(shmid, NULL, 0);
	if (map == NULL)
	{	Log(0, "Can't attach shared memory: %s!", strerror(errno));
		exit(1);
	} else if (created)
#endif
		do_initmap();
}

#ifdef SOFT_RECONFIG
/* Clear map of classes, restart perl and reprocess all prefixes */
void reconfig(void)
{
	struct route_obj *cur;
	int enabled;

	do_initmap();
	prefix_cnt = passive_cnt = 0;
	for (cur = firstroute(route_root); cur; cur = nextroute(cur))
	{
		uint32_t prefix = htonl(cur->ip);

		prefix_cnt++;
		enabled = perlfilter(prefix, cur->prefix_len, cur->community_len, cur->aspath + cur->aspath_len, cur->aspath_len, cur->aspath, cur->nexthop);
		if (!enabled)
		{
			cur->disabled = 1;
			cur->class = 0;
			passive_cnt++;
			continue;
		} else
		{
			cur->disabled = 0;
			perlupdate(prefix, cur->prefix_len, cur->community_len, cur->aspath + cur->aspath_len, cur->aspath_len, cur->aspath, cur->nexthop, 1);
#if NBITS > 0
			cur->class = setclass(cur->aspath + cur->aspath_len, cur->community_len, cur->aspath, cur->aspath_len, prefix, cur->prefix_len);
			chclass(cur);
#endif
		}
	}
	perlupdate_done();
	mapinited = 0;
	Log(1, "Reconfig done");
}
#endif

static int perlfilter(uint32_t prefix, int prefix_len, int community_len, uint32_t *community,
                      int aspath_len, uint32_t *aspath, uint32_t nexthop)
{
	char *prc;
	char sprefix[32], scommunity[256], saspath[256];
	SV *svcommunity, *svaspath, *svprefix, *svnexthop, *svret;
	STRLEN n_a;
	int rc;

	dSP;
	if (plfilter[0] == '\0') return 1;
	svcommunity = perl_get_sv("community", TRUE);
	svaspath    = perl_get_sv("aspath", TRUE);
	svprefix    = perl_get_sv("prefix", TRUE);
	svnexthop   = perl_get_sv("next_hop", TRUE);
	sprintf(sprefix, "%s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
	aspathstr(aspath_len, aspath, saspath, sizeof(saspath));
	communitystr(community_len, community, scommunity, sizeof(scommunity));
	SvREADONLY_off(svcommunity);
	SvREADONLY_off(svaspath);
	SvREADONLY_off(svprefix);
	SvREADONLY_off(svnexthop);
	sv_setpv(svcommunity, scommunity);
	sv_setpv(svaspath, saspath);
	sv_setpv(svprefix, sprefix);
	sv_setpv(svnexthop, inet_ntoa(*(struct in_addr *)&nexthop));
	SvREADONLY_on(svcommunity);
	SvREADONLY_on(svaspath);
	SvREADONLY_on(svprefix);
	SvREADONLY_on(svnexthop);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plfilter, G_EVAL|G_SCALAR);
	SPAGAIN;
	svret = POPs;
	if (SvOK(svret))
		prc = strdup(SvPV(svret, n_a));
	else
		prc = NULL;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plfilter, SvPV(ERRSV, n_a));
		plfilter[0] = '\0';
		prc = NULL;
	}
	if (n_a == 0 && prc)
	{
		free(prc);
		prc = NULL;
	}
	if (prc)
	{ 
		rc = atoi(prc);
		free(prc);
	} else
	{
		rc = 1;
	}
	return rc;
}

static void perlupdate(uint32_t prefix, int prefix_len, int community_len, uint32_t *community,
                       int aspath_len, uint32_t *aspath, uint32_t nexthop, int added)
{
	char sprefix[32], scommunity[256], saspath[256];
	SV *svcommunity, *svaspath, *svprefix, *svnexthop, *svnew;
	STRLEN n_a;

	dSP;
	if (plupdate[0] == '\0') return;
	svcommunity = perl_get_sv("community", TRUE);
	svaspath    = perl_get_sv("aspath", TRUE);
	svprefix    = perl_get_sv("prefix", TRUE);
	svnexthop   = perl_get_sv("next_hop", TRUE);
	svnew       = perl_get_sv("new", TRUE);
	sprintf(sprefix, "%s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
	aspathstr(aspath_len, aspath, saspath, sizeof(saspath));
	communitystr(community_len, community, scommunity, sizeof(scommunity));
	SvREADONLY_off(svcommunity);
	SvREADONLY_off(svaspath);
	SvREADONLY_off(svprefix);
	SvREADONLY_off(svnexthop);
	SvREADONLY_off(svnew);
	sv_setpv(svcommunity, scommunity);
	sv_setpv(svaspath, saspath);
	sv_setpv(svprefix, sprefix);
	sv_setpv(svnexthop, inet_ntoa(*(struct in_addr *)&nexthop));
	sv_setpv(svnew, added ? "1" : "");
	SvREADONLY_on(svcommunity);
	SvREADONLY_on(svaspath);
	SvREADONLY_on(svprefix);
	SvREADONLY_on(svnexthop);
	SvREADONLY_on(svnew);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plupdate, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plupdate, SvPV(ERRSV, n_a));
		plupdate[0] = '\0';
	}
}

static void perlwithdraw(uint32_t prefix, int prefix_len)
{
	char sprefix[32];
	SV *svprefix;
	STRLEN n_a;

	dSP;
	if (plwithdraw[0] == '\0') return;
	svprefix = perl_get_sv("prefix", TRUE);
	sprintf(sprefix, "%s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
	SvREADONLY_off(svprefix);
	sv_setpv(svprefix, sprefix);
	SvREADONLY_on(svprefix);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plwithdraw, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plwithdraw, SvPV(ERRSV, n_a));
		plwithdraw[0] = '\0';
	}
}

static void perlupdate_done(void)
{
	STRLEN n_a;

	dSP;
	if (plupdatedone[0] == '\0') return;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plupdatedone, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plupdatedone, SvPV(ERRSV, n_a));
		plupdatedone[0] = '\0';
	}
}

static void perlkeepalive(int sent)
{
	SV *svsent;
	STRLEN n_a;

	dSP;
	if (plkeepalive[0] == '\0') return;
	svsent = perl_get_sv("sent", TRUE);
	SvREADONLY_off(svsent);
	sv_setpv(svsent, sent ? "1" : "");
	SvREADONLY_on(svsent);
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	PUTBACK;
	perl_call_pv(plkeepalive, G_EVAL|G_SCALAR);
	SPAGAIN;
	PUTBACK;
	FREETMPS;
	LEAVE;
	if (SvTRUE(ERRSV))
	{
		Log(0, "Perl %s() eval error: %s", plkeepalive, SvPV(ERRSV, n_a));
		plkeepalive[0] = '\0';
	}
}

