#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "ipmap.h"

static class_type *map;
static int shmid;
unsigned long int mapkey;

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
#if 1
	fprintf(stdout, "%u %s ", level, str);
	vfprintf(stdout, format, ap);
	fprintf(stdout, "\n");
#endif
	va_end(ap);
	fflush(stdout);
}


#if NBITS<8
static class_type shmgetone(class_type *map, unsigned long addr)
{
	unsigned char bits, mask;
	unsigned int offs = (unsigned int)(ntohl(addr));
	offs >>= (32-MAXPREFIX);
	bits = (offs%(8/NBITS))*NBITS;
	mask = (0xff >> (8-NBITS))<<bits;
	offs /= (8/NBITS);
	return (map[offs] & mask) >> bits;
}
#else
static class_type shmgetone(class_type *map, unsigned long addr)
{
	unsigned int offs = (unsigned int)(ntohl(addr));
	offs >>= (32-MAXPREFIX);
	return map[offs];
}
#endif

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

static void init_map(int argc, char *argv[])
{
	map = NULL;
	shmid = -1;
	signal(SIGINT, sighnd);
	signal(SIGTERM, sighnd);
	signal(SIGQUIT, sighnd);
	atexit(freeshmem);
	shmid = shmget(mapkey, MAPSIZE, 0444);
	if (shmid == -1)
	{
		Log(0, "Can't get shared memory (key %u, size %u): %s!", mapkey, MAPSIZE, strerror(errno));
		exit(1);
	} else
		/* Log(5, "Shared memory segment attached") */ ;
	map = shmat(shmid, NULL, SHM_RDONLY);
	if (map == NULL)
	{	Log(0, "Can't attach shared memory: %s!", strerror(errno));
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	unsigned long int addr;
	mapkey = MAPKEY;
	if (argc>1 && (addr=inet_addr(argv[1]))!=INADDR_NONE)
	{	init_map(0, NULL);
		printf("%s has class %u\n", argv[1], shmgetone(map, addr));
		return 0;
	}
	printf("Usage: %s <ip-addr>\n", argv[0]);
	return 1;
}

