
#include "napc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int napc_init(NapcCtx *ctx, uint16_t port) {
    memset(ctx, 0, sizeof(NapcCtx));
    
    ctx->local_mds = 1472;
    ctx->local_mrds = 65535;
    ctx->local_segs = 64;
    ctx->max_reass = 512;
    ctx->reass_timeout = 5;
    ctx->use_apc = 1;
    ctx->use_time = 0;
    
    ctx->reass = calloc(ctx->max_reass, sizeof(NapcReassembly));
    if (!ctx->reass) return -1;
    
    ctx->socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx->socket_fd < 0) {
        free(ctx->reass);
        return -1;
    }
    
    int buf_size = 4 * 1024 * 1024;
    setsockopt(ctx->socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(ctx->socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    if (port > 0) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_ANY),
            .sin_port = htons(port)
        };
        
        if (bind(ctx->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(ctx->socket_fd);
            free(ctx->reass);
            return -1;
        }
    }
    
    ctx->epoll_fd = epoll_create1(0);
    if (ctx->epoll_fd >= 0) {
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = ctx->socket_fd };
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->socket_fd, &ev);
    }
    
    return 0;
}

void napc_close(NapcCtx *ctx) {
    if (ctx->socket_fd >= 0) close(ctx->socket_fd);
    if (ctx->epoll_fd >= 0) close(ctx->epoll_fd);
    free(ctx->tx_scratch);
    free(ctx->rx_scratch);
    
    for (size_t i = 0; i < ctx->max_reass; i++) {
        for (size_t j = 0; j < ctx->reass[i].num_pieces; j++)
            free(ctx->reass[i].pieces[j].data);
        free(ctx->reass[i].pieces);
    }
    free(ctx->reass);
    memset(ctx, 0, sizeof(NapcCtx));
}
