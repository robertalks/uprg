ifndef CC
CC = gcc
endif

ifndef CFLAGS
CFLAGS += -Wall -O2 -g
endif

ifndef DESTDIR
DESTDIR = /usr/local
endif

all: uprg

clean:
	rm -f *.o
	rm -f uprg

install:
	[ -d $(DESTDIR)/bin ] || mkdir $(DESTDIR)/bin
	install -m 0755 uprg $(DESTDIR)/bin/uprg

uninstall:
	[ -x $(DESTDIR)/bin/uprg ] && rm -f $(DESTDIR)/bin/uprg

uprg: uprg.o
	$(CC) $(CFLAGS) -o $@ $^ -ludev

uprg.o: uprg.c
	$(CC) $(CFLAGS) -c -o $@ $^
