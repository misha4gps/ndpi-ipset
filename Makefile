CC=gcc
# DBG=-g -D DEBUG=1

# Auto-detect installed nDPI major version via ndpi_global_init (ndpi5+ only).
# Override with: make NDPI_VER=4|5
NDPI_VER ?= $(shell \
    printf 'void ndpi_global_init();int main(){ndpi_global_init();return 0;}' | \
    $(CC) -x c - -L/usr/local/lib -L/opt/lib -lndpi -o /dev/null 2>/dev/null \
    && echo 5 || echo 4)
NDPI_INCDIR ?= ./ndpi$(NDPI_VER)

CFLAGS+=$(DBG) -Wformat -Wformat-security -Wall -Werror=format-security \
	-DNDPI_VER=$(NDPI_VER) \
	-I$(NDPI_INCDIR) \
	-I./

IPSET=$(shell (ls -1 /opt/lib/libipset.so* 2>/dev/null || echo -lipset) |head -n 1)
LDFLAGS+=$(IPSET) -L/usr/local/lib -L/opt/lib -lndpi 

SRC=ndpi-ipset.c
BIN=ndpi-ipset

all: $(BIN)

ndpi5/ndpi_define.h: ndpi5/ndpi_define.h.in
	sed -e 's/@NDPI_API_VERSION@/7000/' \
	    -e 's/@NDPI_MAJOR@/5/' \
	    -e 's/@NDPI_MINOR@/0/' \
	    -e 's/@NDPI_PATCH@/0/' \
	    $< > $@

ifeq ($(NDPI_VER),5)
ifeq ($(NDPI_INCDIR),./ndpi5)
$(BIN): ndpi5/ndpi_define.h
endif
endif

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN) *.o ndpi5/ndpi_define.h