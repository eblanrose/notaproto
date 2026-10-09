#ifndef NAPC_INTERNAL_H
#define NAPC_INTERNAL_H

#include "napc.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#ifdef NAPC_DEBUG
#define NLOG(...) do { \
    fprintf(stderr, "[napc %d] ", (int)getpid()); \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); \
  } while (0)
#else
#define NLOG(...) do { } while (0)
#endif


typedef int (*opt_callback)(uint8_t kind, uint8_t *value, size_t len, void *user);

#define NAPC_SCAN_TAIL 48

struct parse_userdata {
    NapcCtx *ctx;
    struct sockaddr_in *src;
    uint8_t *data;
    size_t data_len;
    uint32_t *ident_out;
    uint16_t *frag_offset_out;
    uint16_t *rdos_out;
    int *is_frag;
};


int parse_options(const uint8_t *surplus, size_t surplus_len, opt_callback cb, void *user);
int opt_handler(uint8_t kind, uint8_t *value, size_t len, void *user);

NapcReassembly* find_reassembly(NapcCtx *ctx, uint32_t ident,
                                const struct sockaddr_in *src);
int add_fragment_piece(NapcReassembly *reass, const uint8_t *data, size_t len, uint16_t offset);
int reassemble_and_deliver(NapcCtx *ctx, NapcReassembly *reass, napc_recv_cb recv_cb, struct sockaddr_in *src);

void napc_write_u32be(uint8_t *p, uint32_t v);

int send_fragment(NapcCtx *ctx, struct sockaddr_in *dst, uint32_t ident, int is_last,
                  uint16_t frag_offset, uint16_t rdos, const uint8_t *data, size_t data_len);
size_t build_fragment(NapcCtx *ctx, uint32_t ident, int is_last,
                      uint16_t frag_offset, uint16_t rdos,
                      const uint8_t *data, size_t data_len, uint8_t *packet);

void surplus_add_eol(uint8_t *surplus, size_t *offset, size_t maxlen);
int surplus_add_tlv(uint8_t *surplus, size_t *offset, size_t maxlen,
                    uint8_t kind, uint8_t length, const uint8_t *value);

extern napc_recv_cb g_recv_cb;

#endif
