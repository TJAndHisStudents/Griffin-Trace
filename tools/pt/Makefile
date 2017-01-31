CC=gcc
DISTORM=distorm

all: pt.c distorm3
	$(CC) -O2 -I$(DISTORM)/include -g pt.c $(DISTORM)/distorm3.a -o pt

distorm3:
	make -C $(DISTORM)/make/linux

clean:
	rm -f pt
