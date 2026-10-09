
#include "napc.h"
#include "napc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int napc_send(NapcCtx *ctx, const uint8_t *data, size_t len, struct sockaddr_in *dst) {
    return napc_send_with_opts(ctx, data, len, dst, ctx->use_apc, ctx->use_time, 0, 0);
}

size_t napc_single_max(const NapcCtx *ctx) {
    if (!ctx) return 0;
    size_t overhead = NAPC_OCS_SIZE + 1
                    + (ctx->use_apc ? 6 : 0)
                    + (ctx->use_time ? 12 : 0);
    if (ctx->local_mds <= overhead) return 0;
    return ctx->local_mds - overhead;
}

int napc_send_with_opts(NapcCtx *ctx, const uint8_t *data, size_t len,
                        struct sockaddr_in *dst, int use_apc, int use_time,
                        uint32_t tsval, uint32_t tsecr) {

    if (!ctx || !dst || (len > 0 && !data)) return -1;
    if (len > 65535) return -1;

    size_t max_data = napc_single_max(ctx);
    if (max_data == 0) return -1;

    if (len <= max_data) {
        uint8_t packet[65535];
        size_t pos = len;

        if (len > 0) memcpy(packet, data, len);

        size_t surplus_start = pos;
        pos += 4;

        if (use_apc) {
            uint32_t crc = napc_crc32c(data, len);
            uint8_t apc_val[4];
            apc_val[0] = (crc >> 24) & 0xFF;
            apc_val[1] = (crc >> 16) & 0xFF;
            apc_val[2] = (crc >> 8) & 0xFF;
            apc_val[3] = crc & 0xFF;
            if (surplus_add_tlv(packet, &pos, ctx->local_mds,
                                NAPC_OPT_APC, 4, apc_val) < 0) return -1;
        }

        if (use_time) {
            NapcOptTime t = {
                .kind = NAPC_OPT_TIME,
                .length = NAPC_TIME_LEN - 2,
                .tsval = htonl(tsval),
                .tsecr = htonl(tsecr)
            };
            if (surplus_add_tlv(packet, &pos, ctx->local_mds, NAPC_OPT_TIME,
                                NAPC_TIME_LEN - 2, ((uint8_t*)&t) + 2) < 0) return -1;
        }

        surplus_add_eol(packet, &pos, ctx->local_mds);

        uint32_t ocs = napc_ocs_compute(packet + surplus_start, pos - surplus_start);
        napc_write_u32be(packet + surplus_start, ocs);

        ssize_t sent = sendto(ctx->socket_fd, packet, pos, 0,
                             (struct sockaddr*)dst, sizeof(*dst));
        if (sent > 0) ctx->bytes_sent += sent;
        else NLOG("SEND-FAIL len=%zu errno=%d", len, errno);
        return (sent > 0) ? (int)len : -1;

    } else {
        uint32_t ident = napc_generate_ident();
        NLOG("SEND-FRAG ident=%08x len=%zu", ident, len);

        size_t frag_overhead = 4 + 12 + 1 + (ctx->use_apc ? 6 : 0);
        if (ctx->local_mds <= frag_overhead) return -1;
        size_t max_frag = ctx->local_mds - frag_overhead;

        enum { TXBATCH = 16 };
        size_t need = (size_t)TXBATCH * ctx->local_mds;
        if (ctx->tx_scratch_cap < need) {
            uint8_t *p = realloc(ctx->tx_scratch, need);
            if (!p) return -1;
            ctx->tx_scratch = p;
            ctx->tx_scratch_cap = need;
        }
        uint8_t *bufs = ctx->tx_scratch;

        struct mmsghdr mm[TXBATCH];
        struct iovec iov[TXBATCH];
        uint32_t offset = 0;
        size_t remaining = len;
        int fail = 0;

        while (remaining > 0 && !fail) {
            int n = 0;
            memset(mm, 0, sizeof(mm));

            while (n < TXBATCH && remaining > 0) {
                size_t chunk = (remaining > max_frag) ? max_frag : remaining;
                int is_last = (chunk >= remaining);
                uint16_t rdos = is_last ? (uint16_t)(offset + chunk) : 0;

                uint8_t *pkt = bufs + (size_t)n * ctx->local_mds;
                size_t plen = build_fragment(ctx, ident, is_last, (uint16_t)offset,
                                             rdos, data + offset, chunk, pkt);
                if (plen == 0) { fail = 1; break; }

                iov[n].iov_base = pkt;
                iov[n].iov_len = plen;
                mm[n].msg_hdr.msg_iov = &iov[n];
                mm[n].msg_hdr.msg_iovlen = 1;
                mm[n].msg_hdr.msg_name = dst;
                mm[n].msg_hdr.msg_namelen = sizeof(*dst);

                offset += chunk;
                remaining -= chunk;
                n++;
            }
            if (fail || n == 0) break;

            int sent = sendmmsg(ctx->socket_fd, mm, n, 0);
            if (sent < 0) {
                NLOG("SENDMMSG FAIL ident=%08x n=%d errno=%d", ident, n, errno);
                fail = 1;
                break;
            }
            for (int k = 0; k < sent; k++) {
                ctx->frags_sent++;
                ctx->bytes_sent += mm[k].msg_len;
            }
            if (sent < n) {
                NLOG("SENDMMSG PARTIAL ident=%08x sent=%d/%d", ident, sent, n);
                fail = 1;
            }
        }

        if (fail) return -1;
        return (int)len;
    }
}
