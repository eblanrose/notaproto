#include <errno.h>
#include "napc.h"
#include "napc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

napc_recv_cb g_recv_cb = NULL;

void napc_set_recv_cb(NapcCtx *ctx, napc_recv_cb cb) {
    g_recv_cb = cb;
    (void)ctx;
}

int napc_poll(NapcCtx *ctx, int timeout_ms) {
    struct epoll_event events[8];
    int nfds = epoll_wait(ctx->epoll_fd, events, 8, timeout_ms);
    
    if (nfds < 0) return (errno == EINTR) ? 0 : -1;
    
    for (int i = 0; i < nfds; i++) {
        if (events[i].data.fd == ctx->socket_fd) {
            uint8_t buffer[65535];
            struct sockaddr_in src;
            socklen_t src_len = sizeof(src);
            
            ssize_t total = recvfrom(ctx->socket_fd, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&src, &src_len);
            if (total <= 0) continue;
            
            ctx->bytes_recv += total;
            
            uint8_t *payload = buffer;
            size_t payload_len = (size_t)total;
            size_t data_len = payload_len;
            size_t surplus_len = 0;
            
            
            if (payload_len >= 4) {
                for (size_t scan = 0; scan < payload_len - 3; scan++) {
                    uint32_t ocs = ((uint32_t)payload[scan] << 24) | 
                                   ((uint32_t)payload[scan+1] << 16) |
                                   ((uint32_t)payload[scan+2] << 8) | 
                                   payload[scan+3];
                    
                    size_t test_surplus_len = payload_len - scan;
                    uint32_t computed = napc_ocs_compute(payload + scan, test_surplus_len);
                    
                    if (ocs == computed) {
                        int valid = 0;
                        if (scan == 0) {
                            valid = 1;
                        } else if (scan % 2 == 0) {
                            valid = 1;
                        } else if (payload[scan-1] == 0) {
                            valid = 1;
                        }
                        
                        if (valid) {
                            if (scan > 0 && (scan % 2 == 1) && payload[scan-1] == 0) {
                                data_len = scan - 1;
                            } else {
                                data_len = scan;
                            }
                            surplus_len = test_surplus_len;
                            break;
                        }
                    }
                }
            }
            
            
            if (surplus_len > 0 && data_len > 0 && (data_len % 2 == 0) && payload[data_len-1] == 0) {
                if ((data_len - 1) % 2 == 1) {
                    data_len--;
                }
            }
            
            uint8_t *udp_data = payload;
            uint8_t *surplus = payload + data_len;
            
            uint32_t frag_ident = 0;
            uint16_t frag_offset = 0;
            uint16_t frag_rdos = 0;
            int is_frag = 0;
            
            if (surplus_len > 4) {
                struct parse_userdata ud = {
                    .ctx = ctx,
                    .src = &src,
                    .data = udp_data,
                    .data_len = data_len,
                    .ident_out = &frag_ident,
                    .frag_offset_out = &frag_offset,
                    .rdos_out = &frag_rdos,
                    .is_frag = &is_frag,
                };
                
                parse_options(surplus + 4, surplus_len - 4, opt_handler, &ud);
            }
            
            if (is_frag) {
                NapcReassembly *reass = find_reassembly(ctx, frag_ident);
                if (reass) {
                    add_fragment_piece(reass, udp_data, data_len, frag_offset);
                    
                    if (frag_rdos > 0) {
                        reass->have_terminal = 1;
                        reass->total_rdos = frag_rdos;
                    }
                    
                    if (reass->have_terminal) {
                        reassemble_and_deliver(ctx, reass, g_recv_cb, &src);
                    }
                }
            } else {
                if (g_recv_cb && data_len > 0) {
                    g_recv_cb(ctx, udp_data, data_len, &src, 0);
                }
            }
        }
    }
    
    
    time_t now = (time_t)napc_monotonic_ms() / 1000;
    for (size_t i = 0; i < ctx->max_reass; i++) {
        if (ctx->reass[i].pieces && 
            now - ctx->reass[i].start_time > ctx->reass_timeout) {
            for (size_t j = 0; j < ctx->reass[i].num_pieces; j++)
                free(ctx->reass[i].pieces[j].data);
            free(ctx->reass[i].pieces);
            memset(&ctx->reass[i], 0, sizeof(NapcReassembly));
        }
    }
    
    return nfds;
}
