
CFLAGS = -funsigned-char -Wall -g `perl -MExtUtils::Embed -e ccopts`
LFLAGS = -Wall -g `perl -MExtUtils::Embed -e ldopts`

all:	bgpd

bgpd:	bgpd.o bgptable.o config.o
	gcc -o bgpd bgpd.o bgptable.o config.o $(LFLAGS)

bgpd.o:	bgpd.c bgpd.h
	gcc $(CFLAGS) -o bgpd.o -c -g bgpd.c

bgptable.o:	bgptable.c bgpd.h ipmap.h
	gcc $(CFLAGS) -o bgptable.o -c -g bgptable.c

config.o:	config.c bgpd.c
	gcc $(CFLAGS) -o config.o -c -g config.c
