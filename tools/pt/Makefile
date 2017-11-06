CC=gcc
DISTORM=distorm

all: pt.c blame.c distorm3
	$(CC) -O2 -I$(DISTORM)/include -g pt.c $(DISTORM)/distorm3.a -o pt
	$(CC) -O2 -I$(DISTORM)/include -g blame.c $(DISTORM)/distorm3.a -o blame

distorm3:
	make -C $(DISTORM)/make/linux

clean:
	rm -f pt
