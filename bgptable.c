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
#include <unistd.h>
#include <XSUB.h>

#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif

#include "bgpd.h"
#include "ipmap.h"

struct route_obj {
	ulong ip;
	char prefix_len;
	class_type class;
	struct route_obj *left, *right, *parent;
};

static struct route_obj *route_root = NULL;
class_type *map;
static int last_ballanced=0;
int prefix_cnt;

static PerlInterpreter *perl = NULL;

static struct route_obj *findroute(struct route_obj *new, int addnew, int *added);
static void mapsetclass(ulong from, ulong to, class_type class);

#if 1
void boot_DynaLoader(CV *cv);

static XS(perl_initclass)
{
  dXSARGS;
  char *ip;
  int class;
  STRLEN n_a;
  char *p;
  int preflen=24;
  unsigned long ipaddr;

  if (items != 2)
  { Log(0, "Wrong params number to setclass (need 2, exist %d)", items);
    XSRETURN_EMPTY;
  }
  ip    = (char *)SvPV(ST(0), n_a); if (n_a == 0) ip    = "";
  class = SvIV(ST(1));
  p=strchr(ip, '/');
  if (p)
  { *p++='\0';
    preflen=atoi(p);
  }
  ipaddr = ntohl(inet_addr(ip));
  mapsetclass(ipaddr, ipaddr+(1<<(32-preflen))-1, (class_type)class);
  XSRETURN_EMPTY;
}

static void xs_init(void)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
  newXS("initclass",  perl_initclass,  file);
}
#endif

static void exitperl(void)
{
  if (perl)
  {
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}

static int PerlStart(void)
{
   int rc;
   char *perlargs[]={"", "", NULL};

   perlargs[1] = perlfile;
   if (access(perlfile, R_OK))
   { Log(0, "Can't read %s: %s", perlfile, strerror(errno));
     return 1;
   }
   perl = perl_alloc();
   perl_construct(perl);
#if 1
   rc=perl_parse(perl, xs_init, 2, perlargs, NULL);
#else
   rc=perl_parse(perl, NULL, 2, perlargs, NULL);
#endif
   if (rc)
   { Log(0, "Can't parse %s", perlfile);
     perl_destruct(perl);
     perl_free(perl);
     perl=NULL;
     return 1;
   }
   atexit(exitperl);
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
     Log(0, "Perl eval error: %s\n", SvPV(ERRSV, n_a));
     exit(4);
   }
}

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
   sv_setpv(svcommunity, community);
   sv_setpv(svaspath, aspath);
   sv_setpv(svprefix, prefix);
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
     Log(0, "Perl eval error: %s\n", SvPV(ERRSV, n_a));
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

static class_type setclass(ulong *community, int community_len,
                           ushort *aspath, int aspath_len,
                           ulong prefix, ushot prefix_len)
{
	int i;
	char saspath[256], scommunity[256], sprefix[32], *p;
	ushort firstas, secondas;

	saspath[0] = scommunity[0] = '\0';
	p = saspath;
	for (i=0; i<aspath_len; i++)
	{	if (*saspath) *p++=' ';
		sprintf(p, "%u", ntohs(aspath[i]));
		p+=strlen(p);
		if (p-saspath+15>sizeof(saspath))
			break;
	}
	p = scommunity;
	for (i=0; i<community_len; i++)
	{	if (*scommunity) *p++=' ';
		firstas=ntohs(*(ushort *)(community+i));
		secondas=ntohs(((ushort *)(community+i))[1]);
		if (firstas == 0xffff && secondas == 0xff01)
			strcpy(p, "no-export");
		else if (firstas == 0xffff && secondas == 0xff02)
			strcpy(p, "no-advertise");
		else if (firstas == 0xffff && secondas == 0xff03)
			strcpy(p, "no-export-subconfed");
		else
			sprintf(p, "%u:%u", firstas, secondas);
		p+=strlen(p);
		if (p-scommunity+20>sizeof(scommunity))
			break;
	}
	snprintf(sprefix, sizeof(sprefix), "%s/%u", inet_ntoa(*((struct in_addr *)&prefix)), prefix_len);
	return perlsetclass(scommunity, saspath, sprefix);
}

static int compare(struct route_obj *a, struct route_obj *b)
{
	if (a->ip>b->ip) return 1;
	if (a->ip<b->ip) return -1;
	if (a->prefix_len>b->prefix_len) return 1;
	if (a->prefix_len<b->prefix_len) return -1;
	return 0;
}

static struct route_obj *nextroute(struct route_obj *cur)
{
	struct route_obj *newcur;

	if (!cur) return NULL;
	if (!cur->right)
	{	while(cur->parent)
		{	newcur = cur->parent;
			if (newcur->right != cur)
				return newcur;
			cur = newcur;
		}
		return NULL;
	}
	for (cur=cur->right; cur->left; cur=cur->left);
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
			if (++curdepth>maxdepth) maxdepth=curdepth;
			continue;
		}
		if (r->right)
		{	r = r->right;
			if (++curdepth>maxdepth) maxdepth=curdepth;
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


static struct route_obj *ballance(struct route_obj *r)
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
		pp=findroute(r, 2, &i);
		if (pp==NULL || i==0 || pp!=r)
		{	Log(0, "Internal error!");
			exit(2);
		}
		r = p;
		last_ballanced = 0;
	}
}

static void ballance_tree(void)
{
	struct route_obj *r, *p;
	int depth;

	last_ballanced = 0;
	r = route_root;
	if (r==NULL) return;
	depth = routedepth(route_root);
	if (depth<maxdepth)
	{	Log(6, "Binary tree ballancing not needed (depth %u)", depth);
		return;
	}
	Log(5, "Binary tree ballancing (depth %u)...", depth);
	while (1)
	{	r = ballance(r);
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
				if (depth>maxdepth)
				{	maxdepth = depth+1;
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

static struct route_obj *findroute(struct route_obj *new, int addnew, int *added)
{
	struct route_obj *cur, *p, **newcur;
	int i;
	if (added) *added=0;
	for (cur=route_root; ; cur = *newcur)
	{	if (cur == NULL)
		{	newcur = &route_root;
		} else
		{	i=compare(new, cur);
			if (i==0) return cur;
			if (i>0) newcur=&cur->right;
			else newcur=&cur->left;
		}
		if (*newcur==NULL)
		{	if (addnew==0) return NULL;
			if (addnew==-1) /* find nearest bigger */
			{	if (newcur == &cur->right)
					return nextroute(cur);
				else
					return cur;
			}
			if (addnew==1)
			{	p = malloc(sizeof(*cur));
				if (p==NULL)
				{	Log(0, "Memory allocation fail!");
					exit(1);
				}
				memcpy(p, new, sizeof(*cur));
				if (p->right) p->right->parent = p;
				if (p->left) p->left->parent = p;
				prefix_cnt++;
			} else
				p = new;
			p->parent = cur;
			*newcur = p;
			if (added) *added=1;
			if (ballance_cnt && last_ballanced++ >= ballance_cnt)
				ballance_tree();
			return p;
		}
	}
}

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
			if (findroute(route->right, 2, NULL)!=route->right)
			{	Log(0, "Internal error in delroute!");
				exit(3);
			}
		}
	}
	free(route);
	if (ballance_cnt && last_ballanced++ >= ballance_cnt)
		ballance_tree();
	prefix_cnt--;
}

#if NBITS<=8
static void shmemset(class_type *map, int offs, char class, unsigned int size)
{
	memset(&map[offs], class, size*sizeof(class_type));
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

static void mapsetclass(ulong from, ulong to, class_type class)
{
#if MAXPREFIX < 32
	from>>=(32-MAXPREFIX);
	if (to+1 == 0)
		to=0x80000000ul>>(31-MAXPREFIX);
	else
		to=(to+1)>>(32-MAXPREFIX);
	if (from==to)
		return;
#else // MAXPREFIX == 32
	to++;
#endif // MAXPREFIX == 32
#if NBITS == 16
	{	int i;
		i=from;
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
	{	ulong firstbyte, lastbyte;
		char mask1, mask2;
		firstbyte = from/(8/NBITS);
		lastbyte = (to-1)/(8/NBITS);
		mask1 = (0xff<<((from-firstbyte*(8/NBITS))*NBITS)) & 0xff;
		mask2 = 0xff>>(8-((to-lastbyte*(8/NBITS)))*NBITS);
#if NBITS == 1
		class = (class ? 0xff : 0);
#elif NBITS == 2
		class |= (class<<2) | (class<<4) | (class<<6);
#else // NBITS == 4
		class |= class<<4;
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
		if (firstbyte<=lastbyte)
			shmemset(map, firstbyte, class, lastbyte-firstbyte+1);
	}
#endif // NBITS
}

static int chclass(struct route_obj *obj)
{
	struct route_obj route, *r;
	ulong last_ip;

	memcpy(&route, obj, sizeof(route));
	last_ip = route.ip+(0xfffffffful>>(int)route.prefix_len);
	r = obj;
	for (;;)
	{	r = nextroute(r);
		if (r==NULL || r->ip>last_ip)
		{	mapsetclass(route.ip, last_ip, route.class);
			return 0;
		}
		if (r->ip < route.ip) continue;
		if (route.ip != r->ip)
			mapsetclass(route.ip, r->ip-1, route.class);
		route.ip = r->ip+(0xfffffffful>>(int)r->prefix_len)+1;
		if (route.ip==0 || route.ip>last_ip) return 0;
	}
}

void withdraw(ulong prefix, int prefix_len)
{
	struct route_obj r, parent, *p, *pp;

	r.ip=ntohl(prefix); r.prefix_len=prefix_len;
	p=findroute(&r, 0, NULL);
	if (p==NULL)
	{	Log(0, "Can't withdraw unexistant route %s/%u",
		    inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
		return;
	}
	/* find parent route */
	parent.ip=ntohl(prefix); parent.prefix_len=(ushort)prefix_len;
	parent.class = 0;
	while (parent.prefix_len)
	{	parent.prefix_len--;
		parent.ip &= 0xfffffffful<<(32-(int)parent.prefix_len);
		if ((pp = findroute(&parent, 0, NULL)) != NULL)
		{	parent.class = pp->class;
			break;
		}
	}
	/* modify classes */
	if (p->class != parent.class)
	{	p->class = parent.class;
		chclass(p);
	}
	Log(2, "Withdraw route %s/%u", inet_ntoa(*(struct in_addr *)&prefix), prefix_len);
	/* remove route */
	delroute(p);
}

void update(ulong prefix, int prefix_len, int community_len, ulong *community,
            int aspath_len, ushort *aspath)
{
	struct route_obj r, *p;
	int added;

	r.class = setclass(community, community_len, aspath, aspath_len, prefix, prefix_len);
	r.ip = ntohl(prefix);
	r.prefix_len = (ushort)prefix_len;
	r.left = r.right = r.parent = NULL;
	p = findroute(&r, 1, &added);
	if (!p)
	{	Log(0, "Internal error!");
		exit(2);
	}
	Log(2, "Updated %sroute %s/%u, class %u",
	    (added ? "" : "existing "),
	    inet_ntoa(*(struct in_addr *)&prefix), prefix_len, r.class);
	if (!added && p->class == r.class)
		return;
	if (!added) p->class = r.class;
	chclass(p);
}

void reset_table(void)
{
	struct route_obj *cur = route_root, *p;

	while (cur)
	{	if (cur->left)
			cur=cur->left;
		else if (cur->right)
			cur=cur->right;
		else
		{	p=cur->parent;
			free(cur);
			if (p==NULL) break;
			if (p->left == cur)
				p->left=NULL;
			else
				p->right=NULL;
			cur=p;
		}
	}
	route_root = NULL;
	Log(2, "BGP table cleared");
	mapsetclass(0, 0xfffffffful, 0);
	last_ballanced = 0;
	prefix_cnt = 0;
	exitperl();
	PerlStart();
	if (perl==NULL)
		exit(4);
	Log(2, "Perl loaded");
	perlinitmap();
}

void keepalive(void)
{
	Log(5, "KeepAlive, total %u prefixes", prefix_cnt);
}

static int shmid;

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

static void sighnd(int signo)
{
	Log(1, "Program terminated by signal %u", signo);
	exit(3);
}

void init_map(int argc, char *argv[])
{
	key_t k;
	if (argc>1 && isdigit(argv[1][0]))
		k = atol(argv[1]);
	else
		k = mapkey;
	map = NULL;
	shmid = -1;
	signal(SIGINT, sighnd);
	signal(SIGTERM, sighnd);
	signal(SIGQUIT, sighnd);
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
	} else
		Log(5, "Shared memory segment attached");
	map = shmat(shmid, NULL, 0);
	if (map == NULL)
	{	Log(0, "Can't attach shared memory: %s!", strerror(errno));
		exit(1);
	}
}
