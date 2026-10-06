CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=

# _FILE_OFFSET_BITS is not optional: without it off_t is 32 bits on 32-bit
# hosts and every >2GiB test silently breaks.
CPPFLAGS += -D_FILE_OFFSET_BITS=64

all: tarx

tarx: tarx.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

test: tarx
	@t/run.sh

clean:
	rm -f tarx
	rm -rf t/tmp

.PHONY: all test clean
