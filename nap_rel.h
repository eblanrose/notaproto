#ifndef NAP_REL_H
#define NAP_REL_H


#include "nap.h"
#include <stdint.h>

#define NAP_REL_WINDOW      64      /* unacked *parts* in flight */
#define NAP_REL_TX_QUEUE    128     /* whole messages waiting for window */
#define NAP_REL_RX_PENDING  64      /* out-of-order parts awaiting the gap */
#define NAP_REL_RTO_MS      300     /* first retransmit timeout */
#define NAP_REL_RTO_MAX_MS  2000    /* backoff cap */
#define NAP_REL_MAX_RETRIES 20      /* give up after this many retransmits */
#define NAP_REL_FAST_RETX_MS 5
#define NAP_REL_FAST_RETX_WINDOW_MS 500
#define NAP_REL_MAX_INFLIGHT_BYTES  (512u * 1024u)
#define NAP_REL_MAX_MSG       (1024u * 1024u)
#define NAP_REL_TX_QUEUE_BYTES (32u * 1024u * 1024u)

typedef int (*nap_rel_tx_fn)(void *user, const uint8_t *packet, size_t len);

typedef void (*nap_rel_deliver_fn)(void *user, uint8_t type,
                                   const uint8_t *data, size_t len);

typedef struct {
    uint8_t *data;
    size_t   len;
    uint16_t seq;
    uint8_t  type;
    uint64_t last_tx_ms;
    uint64_t rto_ms;
    uint32_t retries;
} NapRelFrame;

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   sent;
    uint16_t seq_base;
    uint16_t parts_sent;
    uint8_t  type;
    uint32_t sid;
} NapRelQueued;

typedef struct NapRel {
    NapRelFrame inflight[NAP_REL_WINDOW];
    size_t      inflight_n;
    uint64_t    inflight_bytes;
    NapRelQueued tx_queue[NAP_REL_TX_QUEUE];
    size_t      tx_queue_n;
    size_t      tx_queue_bytes;
    size_t      chunk;
    uint16_t    tx_seq;
    uint16_t    last_cum;
    int         fast_retx;
    uint64_t    fast_retx_until;

    uint16_t    rx_expected;
    NapRelFrame rx_pending[NAP_REL_RX_PENDING];
    size_t      rx_pending_n;
    uint8_t    *rx_acc;
    size_t      rx_acc_cap;
    size_t      rx_acc_have;
    size_t      rx_acc_total;
    uint8_t     rx_acc_type;

    uint32_t    tx_dropped;
} NapRel;

int      nap_rel_is_control(uint8_t type);
NapRel*  nap_rel_create(size_t chunk);
void     nap_rel_destroy(NapRel *rel);

int      nap_rel_has_room(NapRel *rel, size_t len);

int      nap_rel_send(NapRel *rel, nap_rel_tx_fn tx, void *user,
                      uint32_t session_id, uint8_t type,
                      const uint8_t *data, size_t len);

int      nap_rel_tick(NapRel *rel, nap_rel_tx_fn tx, void *user);

void     nap_rel_on_ack(NapRel *rel, uint16_t cum_next);

int      nap_rel_recv(NapRel *rel, uint16_t seq, uint8_t type,
                      const uint8_t *data, size_t len,
                      nap_rel_deliver_fn deliver, void *user);

#endif
