#include <errno.h>
#include "napc.h"
#include "napc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

napc_recv_cb g_recv_cb = NULL;

void napc_set_recv_cb(NapcCtx *ctx, napc_recv_cb cb) {
    if (ctx) ctx->recv_cb = cb;
    g_recv_cb = cb;
}

static uint32_t read_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void handle_datagram(NapcCtx *ctx, uint8_t *payload, size_t total,
                            struct sockaddr_in *src) {
    ctx->bytes_recv += total;

    if (total > ctx->local_mds) {
        NLOG("DROP oversized total=%zu", total);
        return;
    }

    size_t data_len = 0;
    size_t surplus_len = 0;
    if (total >= 4) {
        size_t scan_lo = (total > NAPC_SCAN_TAIL) ? total - NAPC_SCAN_TAIL : 0;
        for (size_t scan = scan_lo; scan + 4 <= total; scan++) {
            if (read_u32be(payload + scan) ==
                napc_ocs_compute(payload + scan, total - scan)) {
                data_len = scan;
                surplus_len = total - scan;
                break;
            }
        }
    }

    if (surplus_len == 0) {
        NLOG("DROP no-framing total=%zu", total);
        return;
    }

    uint32_t frag_ident = 0;
    uint16_t frag_offset = 0;
    uint16_t frag_rdos = 0;
    int is_frag = 0;

    if (surplus_len > 4) {
        struct parse_userdata ud = {
            .ctx = ctx,
            .src = src,
            .data = payload,
            .data_len = data_len,
            .ident_out = &frag_ident,
            .frag_offset_out = &frag_offset,
            .rdos_out = &frag_rdos,
            .is_frag = &is_frag,
        };

        if (parse_options(payload + data_len + 4, surplus_len - 4,
                          opt_handler, &ud) < 0) {
            NLOG("DROP parse-fail data_len=%zu total=%zu", data_len, total);
            return;
        }
    }

    napc_recv_cb cb = ctx->recv_cb ? ctx->recv_cb : g_recv_cb;
    if (!cb) return;

    if (is_frag) {
        if (data_len == 0) return;

        NapcReassembly *reass = find_reassembly(ctx, frag_ident, src);
        if (!reass) return;
        if (add_fragment_piece(reass, payload, data_len, frag_offset) < 0)
            return;
        NLOG("FRAG ident=%08x off=%u len=%zu rdos=%u pieces=%u term=%d",
             frag_ident, frag_offset, data_len, frag_rdos,
             reass->num_pieces, reass->have_terminal);

        if (frag_rdos > 0) {
            reass->have_terminal = 1;
            reass->total_rdos = frag_rdos;
        }

        reassemble_and_deliver(ctx, reass, cb, src);
    } else if (data_len > 0) {
        cb(ctx, payload, data_len, src, 0);
    }
}

int napc_poll(NapcCtx *ctx, int timeout_ms) {
    if (!ctx) return -1;

    struct epoll_event events[32];
    int nfds = epoll_wait(ctx->epoll_fd, events, 32, timeout_ms);

    if (nfds < 0) return (errno == EINTR) ? 0 : -1;

    int handled = 0;
    for (int i = 0; i < nfds; i++) {
        if (events[i].data.fd != ctx->socket_fd) continue;

        {
            enum { RXBATCH = 16 };
            size_t need = (size_t)RXBATCH * ctx->local_mds;
            if (ctx->rx_scratch_cap < need && need <= 1024 * 1024) {
                uint8_t *p = realloc(ctx->rx_scratch, need);
                if (p) {
                    ctx->rx_scratch = p;
                    ctx->rx_scratch_cap = need;
                }
            }
            if (ctx->rx_scratch_cap >= need) {
                uint8_t *bufs = ctx->rx_scratch;
                for (;;) {
                    struct mmsghdr mm[RXBATCH];
                    struct iovec iov[RXBATCH];
                    struct sockaddr_in src[RXBATCH];

                    memset(mm, 0, sizeof(mm));
                    for (int k = 0; k < RXBATCH; k++) {
                        iov[k].iov_base = bufs + (size_t)k * ctx->local_mds;
                        iov[k].iov_len = ctx->local_mds;
                        mm[k].msg_hdr.msg_iov = &iov[k];
                        mm[k].msg_hdr.msg_iovlen = 1;
                        mm[k].msg_hdr.msg_name = &src[k];
                        mm[k].msg_hdr.msg_namelen = sizeof(src[k]);
                    }

                    int got = recvmmsg(ctx->socket_fd, mm, RXBATCH, MSG_DONTWAIT, NULL);
                    if (got < 0) {
                        if (errno == EINTR) continue;
                        break;
                    }
                    for (int k = 0; k < got; k++) {
                        if (mm[k].msg_hdr.msg_flags & MSG_TRUNC) continue;
                        handled++;
                        if (mm[k].msg_len == 0) continue;
                        handle_datagram(ctx, bufs + (size_t)k * ctx->local_mds,
                                        (size_t)mm[k].msg_len, &src[k]);
                    }
                    if (got < RXBATCH) break;
                }
            } else for (;;) {
                uint8_t buffer[65535];
                struct sockaddr_in src;
                socklen_t src_len = sizeof(src);

                ssize_t n = recvfrom(ctx->socket_fd, buffer, sizeof(buffer),
                                     MSG_DONTWAIT, (struct sockaddr*)&src, &src_len);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                handled++;
                if (n == 0) continue;

                handle_datagram(ctx, buffer, (size_t)n, &src);
            }
        }
    }

    time_t now = (time_t)(napc_monotonic_ms() / 1000);
    for (size_t i = 0; i < ctx->max_reass; i++) {
        if (ctx->reass[i].pieces &&
            now - ctx->reass[i].start_time > ctx->reass_timeout) {
            for (size_t j = 0; j < ctx->reass[i].num_pieces; j++)
                free(ctx->reass[i].pieces[j].data);
            free(ctx->reass[i].pieces);
            memset(&ctx->reass[i], 0, sizeof(NapcReassembly));
        }
    }

    if (ctx->post_drain) ctx->post_drain(ctx);

    return handled;
}
