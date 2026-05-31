CC       = cc
CFLAGS   = -Wall -O2 -fPIC -D_GNU_SOURCE
AR       = ar
ARFLAGS  = rcs

NAPC_DIR = napc
NAPC_SRC = $(NAPC_DIR)/napc_utils.c \
           $(NAPC_DIR)/napc_options.c \
           $(NAPC_DIR)/napc_fragment.c \
           $(NAPC_DIR)/napc_send.c \
           $(NAPC_DIR)/napc_recv.c \
           $(NAPC_DIR)/napc_init.c

NAP_SRC  = nap_client.c \
           nap_server.c

LIB_SRC  = $(NAPC_SRC) $(NAP_SRC)
LIB_OBJ  = $(LIB_SRC:.c=.o)

INCLUDES = -I. -I$(NAPC_DIR)

ifdef DEBUG
    CFLAGS := -Wall -g -fPIC -D_GNU_SOURCE
else
    CFLAGS += -flto -fdata-sections -ffunction-sections
endif

.PHONY: all clean

all: libnotaproto.a

libnotaproto.a: $(LIB_OBJ)
	$(AR) $(ARFLAGS) $@ $^

libnotaproto.so: $(LIB_OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.o $(NAPC_DIR)/*.o *.a *.so
