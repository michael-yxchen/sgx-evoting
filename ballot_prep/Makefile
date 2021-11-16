CC=gcc

CFLAGS += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs json-c)

OBJ=bps.o

all:  bps

bps: $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS) -lgmp 
