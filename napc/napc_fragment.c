
#include "napc.h"
#include "napc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static int src_matches(const NapcReassembly *reass, const struct sockaddr_in *src) {
    return reass->src.sin_family == src->sin_family &&
           reass->src.sin_port == src->sin_port &&
           reass->src.sin_addr.s_addr == src->sin_addr.s_addr;
}

size_t build_fragment(NapcCtx *ctx, uint32_t ident, int is_last,
                      uint16_t frag_offset, uint16_t rdos,
                      const uint8_t *data, size_t data_len,
                      uint8_t *packet) {
    if (!ctx || (data_len > 0 && !data)) return 0;

    size_t pos = 0;

    if (data_len > 0) {
        memcpy(packet, data, data_len);
        pos = data_len;
    }

    size_t surplus_start = pos;
    pos += 4;

    if (!is_last) {
        NapcOptFragNonTerm frag = {
            .kind = NAPC_OPT_FRAG,
            .length = NAPC_FRAG_LEN_NONTERM,
            .frag_start = htons(0),
            .ident = htonl(ident),
            .frag_offset = htons(frag_offset)
        };
        if (pos + sizeof(frag) > ctx->local_mds) return 0;
        memcpy(packet + pos, &frag, sizeof(frag));
        pos += sizeof(frag);
    } else {
        NapcOptFragTerm frag = {
            .kind = NAPC_OPT_FRAG,
            .length = NAPC_FRAG_LEN_TERM,
            .frag_start = htons(0),
            .ident = htonl(ident),
            .frag_offset = htons(frag_offset),
            .rdos = htons(rdos)
        };
        if (pos + sizeof(frag) > ctx->local_mds) return 0;
        memcpy(packet + pos, &frag, sizeof(frag));
        pos += sizeof(frag);
    }

    if (ctx->use_apc) {
        uint32_t crc = napc_crc32c(data, data_len);
        uint8_t apc_val[4];
        apc_val[0] = (crc >> 24) & 0xFF;
        apc_val[1] = (crc >> 16) & 0xFF;
        apc_val[2] = (crc >> 8) & 0xFF;
        apc_val[3] = crc & 0xFF;
        if (surplus_add_tlv(packet, &pos, ctx->local_mds,
                            NAPC_OPT_APC, 4, apc_val) < 0) return 0;
    }

    surplus_add_eol(packet, &pos, ctx->local_mds);

    uint32_t ocs = napc_ocs_compute(packet + surplus_start, pos - surplus_start);
    napc_write_u32be(packet + surplus_start, ocs);
    return pos;
}

int send_fragment(NapcCtx *ctx, struct sockaddr_in *dst,
                  uint32_t ident, int is_last,
                  uint16_t frag_offset, uint16_t rdos,
                  const uint8_t *data, size_t data_len) {
    if (!ctx || !dst || (data_len > 0 && !data)) return -1;

    uint8_t packet[65535];
    size_t plen = build_fragment(ctx, ident, is_last, frag_offset, rdos,
                                 data, data_len, packet);
    if (plen == 0) return -1;

    ssize_t sent = sendto(ctx->socket_fd, packet, plen, 0,
                          (struct sockaddr*)dst, sizeof(*dst));
    if (sent > 0) {
        ctx->frags_sent++;
        ctx->bytes_sent += sent;
    } else {
        NLOG("FRAGSEND FAIL ident=%08x off=%u last=%d len=%zu errno=%d",
             ident, frag_offset, is_last, data_len, errno);
    }
    return (sent > 0) ? 0 : -1;
}

NapcReassembly* find_reassembly(NapcCtx *ctx, uint32_t ident,
                                const struct sockaddr_in *src) {
    if (ctx->reass_hint < ctx->max_reass) {
        NapcReassembly *h = &ctx->reass[ctx->reass_hint];
        if (h->pieces && h->ident == ident && src_matches(h, src))
            return h;
    }

    for (size_t i = 0; i < ctx->max_reass; i++) {
        NapcReassembly *r = &ctx->reass[i];
        if (r->pieces && r->ident == ident && src_matches(r, src)) {
            ctx->reass_hint = i;
            return r;
        }
    }

    for (size_t i = 0; i < ctx->max_reass; i++) {
        NapcReassembly *r = &ctx->reass[i];
        if (r->pieces == NULL) {
            memset(r, 0, sizeof(NapcReassembly));
            r->ident = ident;
            r->src = *src;
            r->start_time = (time_t)(napc_monotonic_ms() / 1000);
            ctx->reass_hint = i;
            return r;
        }
    }

    time_t now = (time_t)(napc_monotonic_ms() / 1000);
    size_t victim = ctx->max_reass;
    for (size_t i = 0; i < ctx->max_reass; i++) {
        if (now - ctx->reass[i].start_time > ctx->reass_timeout) {
            victim = i;
            break;
        }
    }
    if (victim == ctx->max_reass) {
        NLOG("SLOT-DROP ident=%08x (table full, no expired slot)", ident);
        return NULL;
    }

    NapcReassembly *r = &ctx->reass[victim];
    NLOG("SLOT-EVICT ident=%08x (expired partial, reclaiming for %08x)",
         r->ident, ident);
    for (size_t i = 0; i < r->num_pieces; i++)
        free(r->pieces[i].data);
    free(r->pieces);

    memset(r, 0, sizeof(NapcReassembly));
    r->ident = ident;
    r->src = *src;
    r->start_time = now;
    ctx->reass_hint = (size_t)(r - ctx->reass);
    return r;
}

int add_fragment_piece(NapcReassembly *reass, const uint8_t *data,
                       size_t len, uint16_t offset) {
    if (len == 0) return 0;

    for (size_t i = 0; i < reass->num_pieces; i++) {
        if (reass->pieces[i].offset == offset && reass->pieces[i].len == len)
            return 0;
    }

    if (reass->num_pieces >= reass->cap_pieces) {
        size_t new_cap = reass->cap_pieces ? reass->cap_pieces * 2 : 4;
        NapcFragPiece *new_pieces = realloc(reass->pieces, new_cap * sizeof(NapcFragPiece));
        if (!new_pieces) return -1;
        reass->pieces = new_pieces;
        reass->cap_pieces = new_cap;
    }

    uint8_t *copy = malloc(len);
    if (!copy) return -1;
    memcpy(copy, data, len);

    reass->pieces[reass->num_pieces].data = copy;
    reass->pieces[reass->num_pieces].len = len;
    reass->pieces[reass->num_pieces].offset = offset;
    reass->num_pieces++;
    return 0;
}

static int reassembly_complete(const NapcReassembly *reass) {
    if (!reass->have_terminal || reass->total_rdos == 0) return 0;

    uint32_t total = reass->total_rdos;
    uint32_t covered = 0;
    int progress = 1;

    while (progress && covered < total) {
        progress = 0;
        for (size_t i = 0; i < reass->num_pieces; i++) {
            uint32_t start = reass->pieces[i].offset;
            uint64_t end = (uint64_t)start + reass->pieces[i].len;
            if (start <= covered && end > covered) {
                covered = (end > total) ? total : (uint32_t)end;
                progress = 1;
                if (covered >= total) return 1;
            }
        }
    }
    return covered >= total;
}

static void reassembly_reset(NapcReassembly *reass) {
    for (size_t i = 0; i < reass->num_pieces; i++)
        free(reass->pieces[i].data);
    free(reass->pieces);
    memset(reass, 0, sizeof(NapcReassembly));
}

int reassemble_and_deliver(NapcCtx *ctx, NapcReassembly *reass,
                           napc_recv_cb recv_cb, struct sockaddr_in *src) {
    if (!reass->have_terminal || reass->total_rdos == 0) return 0;

    if (!reassembly_complete(reass)) return 0;

    size_t total = reass->total_rdos;
    uint8_t *result = calloc(1, total);
    if (!result) {
        reassembly_reset(reass);
        return -1;
    }

    for (size_t i = 0; i < reass->num_pieces; i++) {
        NapcFragPiece *p = &reass->pieces[i];
        if (p->offset >= total) continue;
        size_t n = p->len;
        if ((size_t)p->offset + n > total) n = total - p->offset;
        memcpy(result + p->offset, p->data, n);
    }

    if (recv_cb) {
        recv_cb(ctx, result, total, src, reass->ident);
    }

    free(result);
    reassembly_reset(reass);
    return 1;
}
