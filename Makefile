ALL=hittpd
OBJ=hittpd.o http-parser/http_parser.o

CFLAGS=-g -O2 -Wall -Wno-switch -Wextra -Wwrite-strings
CPPFLAGS=-DUSE_SENDFILE -Ihttp-parser

DESTDIR=
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man

hittpd: $(OBJ)

all: $(ALL)

clean: FRC
	rm -f $(ALL) $(OBJ)

install: FRC all
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	install -m0755 $(ALL) $(DESTDIR)$(BINDIR)
	install -m0644 $(ALL:=.1) $(DESTDIR)$(MANDIR)/man8

README: hittpd.8
	mandoc -Tutf8 $< | col -bx >$@

FRC:
