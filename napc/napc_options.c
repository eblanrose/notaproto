
#include "napc.h"
#include "napc_internal.h"
#include <string.h>

int surplus_add_tlv(uint8_t *surplus, size_t *offset, size_t maxlen,
                    uint8_t kind, uint8_t length, const uint8_t *value) {
    size_t pos = *offset;
    size_t opt_total = 2 + length;
    
    if (pos + opt_total > maxlen) return -1;
    
    surplus[pos++] = kind;
    surplus[pos++] = length;
    if (value && length > 0) {
        memcpy(surplus + pos, value, length);
        pos += length;
    }
    *offset = pos;
    return 0;
}

void surplus_add_eol(uint8_t *surplus, size_t *offset, size_t maxlen) {
    if (*offset < maxlen) {
        surplus[(*offset)++] = NAPC_OPT_EOL;
    }
}

int parse_options(const uint8_t *surplus, size_t surplus_len,
                  opt_callback cb, void *user) {
    size_t offset = 0;
    
    while (offset < surplus_len) {
        uint8_t kind = surplus[offset];
        
        if (kind == NAPC_OPT_EOL) break;
        if (kind == NAPC_OPT_NOP) { offset++; continue; }
        if (offset + 2 > surplus_len) return -1;
        
        uint8_t len = surplus[offset + 1];
        size_t opt_len;
        
        if (len == 255) {
            if (offset + 4 > surplus_len) return -1;
            opt_len = (surplus[offset + 2] << 8) | surplus[offset + 3];
            offset += 4;
        } else {
            opt_len = len;
            offset += 2;
        }
        
        if (offset + opt_len - 2 > surplus_len) return -1;
        
        size_t value_len = (len == 255) ? opt_len - 4 : opt_len - 2;
        uint8_t *value = (uint8_t*)(surplus + offset);
        
        if (cb(kind, value, value_len, user) < 0) return -1;
        offset += value_len;
    }
    
    return 0;
}

int opt_handler(uint8_t kind, uint8_t *value, size_t len, void *user) {
    struct parse_userdata *ud = (struct parse_userdata *)user;
    NapcCtx *ctx = ud->ctx;
    
    switch (kind) {
    case NAPC_OPT_APC:
        if (len >= 4 && ctx->use_apc) {
            uint32_t expected = napc_crc32c(ud->data, ud->data_len);
            uint32_t received = (value[0] << 24) | (value[1] << 16) | 
                               (value[2] << 8) | value[3];
            if (expected != received) return -1;
        }
        break;
        
    case NAPC_OPT_FRAG:
        *ud->is_frag = 1;
        if (len >= 8) {
            NapcOptFragNonTerm *frag = (NapcOptFragNonTerm*)(value - 2);
            *ud->ident_out = ntohl(frag->ident);
            *ud->frag_offset_out = ntohs(frag->frag_offset);
            
            if (len >= 10) {
                NapcOptFragTerm *fragt = (NapcOptFragTerm*)(value - 2);
                *ud->rdos_out = ntohs(fragt->rdos);
            }
        }
        break;
        
    case NAPC_OPT_TIME:
        break;  
        
    case NAPC_OPT_REQ:
        if (len >= 4) {
            ctx->req_token = (value[0] << 24) | (value[1] << 16) | 
                            (value[2] << 8) | value[3];
        }
        break;
        
    default:
        break;  
    }
    
    return 0;
}
