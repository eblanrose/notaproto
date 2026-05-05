
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

int napc_send_with_opts(NapcCtx *ctx, const uint8_t *data, size_t len,
                        struct sockaddr_in *dst, int use_apc, int use_time,
                        uint32_t tsval, uint32_t tsecr) {
    
    size_t max_data = ctx->local_mds - NAPC_OCS_SIZE - 4;
    
    if (len <= max_data) {
        uint8_t packet[65535];
        int pos = 0;
        
        memcpy(packet + pos, data, len);
        pos += len;
        
        size_t surplus_start = pos;
        if (pos & 1) packet[pos++] = 0;
        surplus_start = pos;
        
        uint32_t *ocs_ptr = (uint32_t*)(packet + pos);
        pos += 4;
        
        if (use_apc) {
            uint32_t crc = napc_crc32c(data, len);
            uint8_t apc_val[4];
            apc_val[0] = (crc >> 24) & 0xFF;
            apc_val[1] = (crc >> 16) & 0xFF;
            apc_val[2] = (crc >> 8) & 0xFF;
            apc_val[3] = crc & 0xFF;
            surplus_add_tlv(packet, (size_t*)&pos, 65535, NAPC_OPT_APC, 4, apc_val);
        }
        
        if (use_time) {
            NapcOptTime t = {
                .kind = NAPC_OPT_TIME,
                .length = NAPC_TIME_LEN - 2,
                .tsval = htonl(tsval),
                .tsecr = htonl(tsecr)
            };
            surplus_add_tlv(packet, (size_t*)&pos, 65535, NAPC_OPT_TIME,
                           NAPC_TIME_LEN - 2, ((uint8_t*)&t) + 2);
        }
        
        if (pos < (int)sizeof(packet)) {
            packet[pos++] = NAPC_OPT_EOL;
        }
        
        *ocs_ptr = htonl(napc_ocs_compute(packet + surplus_start, pos - surplus_start));
        
        ssize_t sent = sendto(ctx->socket_fd, packet, pos, 0,
                             (struct sockaddr*)dst, sizeof(*dst));
        if (sent > 0) ctx->bytes_sent += sent;
        return (sent > 0) ? (int)len : -1;
        
    } else {
        uint32_t ident = napc_generate_ident();
        size_t max_frag = max_data - 16;
        
        uint16_t offset = 0;
        size_t remaining = len;
        
        while (remaining > 0) {
            size_t chunk = (remaining > max_frag) ? max_frag : remaining;
            int is_last = (chunk >= remaining);
            uint16_t rdos = is_last ? (uint16_t)(offset + chunk) : 0;
            
            if (send_fragment(ctx, dst, ident, is_last, offset, rdos,
                             data + offset, chunk) < 0) {
                return -1;
            }
            
            offset += chunk;
            remaining -= chunk;
        }
        
        return (int)len;
    }
}
