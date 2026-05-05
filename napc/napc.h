
#ifndef NAPC_H
#define NAPC_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>


#define NAPC_HEADER_SIZE    8   
#define NAPC_OCS_SIZE       4   
#define NAPC_OPT_MIN_SIZE   2   
#define NAPC_MAX_SURPLUS    65535


enum {
    NAPC_OPT_EOL    = 0,    
    NAPC_OPT_NOP    = 1,    
    NAPC_OPT_APC    = 2,    
    NAPC_OPT_FRAG   = 3,    
    NAPC_OPT_MDS    = 4,    
    NAPC_OPT_MRDS   = 5,    
    NAPC_OPT_REQ    = 6,    
    NAPC_OPT_RES    = 7,    
    NAPC_OPT_TIME   = 8,    
    NAPC_OPT_AUTH   = 9,    
    NAPC_OPT_EXP    = 127,  
    NAPC_OPT_UCMP   = 192,  
    NAPC_OPT_UENC   = 193,  
    NAPC_OPT_UEXP   = 254,  
};


#define NAPC_FRAG_LEN_NONTERM  10
#define NAPC_FRAG_LEN_TERM     12
#define NAPC_MDS_LEN           4
#define NAPC_MRDS_LEN          5
#define NAPC_REQ_LEN           6
#define NAPC_RES_LEN           6
#define NAPC_TIME_LEN          10



typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
} NapcOptTLV;

typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
    uint16_t frag_start;
    uint32_t ident;
    uint16_t frag_offset;
} NapcOptFragNonTerm;

typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
    uint16_t frag_start;
    uint32_t ident;
    uint16_t frag_offset;
    uint16_t rdos;
} NapcOptFragTerm;

typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
    uint16_t mds;
} NapcOptMDS;

typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
    uint16_t mrds;
    uint8_t  segs;
} NapcOptMRDS;

typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
    uint32_t token;
} NapcOptEcho;

typedef struct __attribute__((packed)) {
    uint8_t  kind;
    uint8_t  length;
    uint32_t tsval;
    uint32_t tsecr;
} NapcOptTime;



typedef struct {
    uint8_t *data;
    size_t   len;
    uint16_t offset;
} NapcFragPiece;

typedef struct {
    uint32_t ident;
    uint16_t total_rdos;
    int      have_terminal;
    NapcFragPiece *pieces;
    size_t   num_pieces;
    size_t   cap_pieces;
    time_t   start_time;
} NapcReassembly;

typedef struct {
    int      socket_fd;
    int      epoll_fd;
    
    uint16_t local_mds;
    uint16_t local_mrds;
    uint8_t  local_segs;
    
    NapcReassembly *reass;
    size_t   max_reass;
    time_t   reass_timeout;
    
    int      use_apc;
    int      use_time;
    int      use_req;
    uint32_t req_token;
    
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint32_t frags_sent;
    uint32_t frags_recv;
} NapcCtx;


typedef void (*napc_recv_cb)(NapcCtx *ctx, const uint8_t *data, size_t len,
                              struct sockaddr_in *src, uint32_t ident);


int  napc_init(NapcCtx *ctx, uint16_t port);
void napc_close(NapcCtx *ctx);
int  napc_poll(NapcCtx *ctx, int timeout_ms);
int  napc_send(NapcCtx *ctx, const uint8_t *data, size_t len, struct sockaddr_in *dst);
int  napc_send_with_opts(NapcCtx *ctx, const uint8_t *data, size_t len,
                         struct sockaddr_in *dst, int use_apc, int use_time,
                         uint32_t tsval, uint32_t tsecr);
void napc_set_recv_cb(NapcCtx *ctx, napc_recv_cb cb);


uint32_t napc_ocs_compute(const uint8_t *surplus, size_t surplus_len);
uint32_t napc_crc32c(const uint8_t *data, size_t len);
uint32_t napc_generate_ident(void);
uint64_t napc_monotonic_ms(void);

#endif 
