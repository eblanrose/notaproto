
#include "napc.h"
#include "napc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int send_fragment(NapcCtx *ctx, struct sockaddr_in *dst,
                  uint32_t ident, int is_last,
                  uint16_t frag_offset, uint16_t rdos,
                  const uint8_t *data, size_t data_len) {
    
    uint8_t packet[65535];
    int pos = 0;
    
    memcpy(packet + pos, data, data_len);
    pos += data_len;
    
    size_t surplus_start = pos;
    if (pos & 1) packet[pos++] = 0;
    surplus_start = pos;
    
    uint32_t *ocs_ptr = (uint32_t*)(packet + pos);
    pos += 4;
    
    if (!is_last) {
        NapcOptFragNonTerm frag = {
            .kind = NAPC_OPT_FRAG,
            .length = NAPC_FRAG_LEN_NONTERM,
            .frag_start = htons(0),
            .ident = htonl(ident),
            .frag_offset = htons(frag_offset)
        };
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
        memcpy(packet + pos, &frag, sizeof(frag));
        pos += sizeof(frag);
    }
    
    surplus_add_eol(packet, (size_t*)&pos, surplus_start + 1500);
    *ocs_ptr = htonl(napc_ocs_compute(packet + surplus_start, pos - surplus_start));
    
    ssize_t sent = sendto(ctx->socket_fd, packet, pos, 0,
                         (struct sockaddr*)dst, sizeof(*dst));
    if (sent > 0) {
        ctx->frags_sent++;
        ctx->bytes_sent += pos;
    }
    return (sent > 0) ? 0 : -1;
}

NapcReassembly* find_reassembly(NapcCtx *ctx, uint32_t ident) {
    for (size_t i = 0; i < ctx->max_reass; i++) {
        if (ctx->reass[i].ident == ident) return &ctx->reass[i];
    }
    
    for (size_t i = 0; i < ctx->max_reass; i++) {
        if (ctx->reass[i].pieces == NULL) {
            ctx->reass[i].ident = ident;
            ctx->reass[i].start_time = (time_t)napc_monotonic_ms() / 1000;
            return &ctx->reass[i];
        }
    }
    
    size_t oldest = 0;
    for (size_t i = 1; i < ctx->max_reass; i++) {
        if (ctx->reass[i].start_time < ctx->reass[oldest].start_time)
            oldest = i;
    }
    
    for (size_t i = 0; i < ctx->reass[oldest].num_pieces; i++)
        free(ctx->reass[oldest].pieces[i].data);
    free(ctx->reass[oldest].pieces);
    
    memset(&ctx->reass[oldest], 0, sizeof(NapcReassembly));
    ctx->reass[oldest].ident = ident;
    ctx->reass[oldest].start_time = (time_t)napc_monotonic_ms() / 1000;
    return &ctx->reass[oldest];
}

int add_fragment_piece(NapcReassembly *reass, const uint8_t *data,
                       size_t len, uint16_t offset) {
    if (reass->num_pieces >= reass->cap_pieces) {
        size_t new_cap = reass->cap_pieces ? reass->cap_pieces * 2 : 4;
        NapcFragPiece *new_pieces = realloc(reass->pieces, new_cap * sizeof(NapcFragPiece));
        if (!new_pieces) return -1;
        reass->pieces = new_pieces;
        reass->cap_pieces = new_cap;
    }
    
    reass->pieces[reass->num_pieces].data = malloc(len);
    memcpy(reass->pieces[reass->num_pieces].data, data, len);
    reass->pieces[reass->num_pieces].len = len;
    reass->pieces[reass->num_pieces].offset = offset;
    reass->num_pieces++;
    return 0;
}

int reassemble_and_deliver(NapcCtx *ctx, NapcReassembly *reass,
                           napc_recv_cb recv_cb, struct sockaddr_in *src) {
    if (!reass->have_terminal) return 0;
    
    size_t total = reass->total_rdos;
    if (total == 0) return -1;
    
    uint8_t *result = calloc(1, total + 65535);
    if (!result) return -1;
    
    for (size_t i = 0; i < reass->num_pieces; i++) {
        if (reass->pieces[i].offset + reass->pieces[i].len <= total) {
            memcpy(result + reass->pieces[i].offset,
                   reass->pieces[i].data,
                   reass->pieces[i].len);
        }
    }
    
    if (recv_cb) {
        recv_cb(ctx, result, total, src, reass->ident);
    }
    
    free(result);
    for (size_t i = 0; i < reass->num_pieces; i++)
        free(reass->pieces[i].data);
    free(reass->pieces);
    memset(reass, 0, sizeof(NapcReassembly));
    return 0;
}
