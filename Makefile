CC=gcc
# DBG=-g -D DEBUG=1
CFLAGS+=$(DBG) -Wformat -Wformat-security -Wall -Werror=format-security \
	-I./ndpi \
	-I./

IPSET=$(shell (ls -1 /opt/lib/libipset.so* 2>/dev/null || echo -lipset) |head -n 1)
LDFLAGS+=$(IPSET) -L/usr/local/lib -L/opt/lib -lndpi 

SRC=ndpi-ipset.c
BIN=ndpi-ipset

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN) *.o