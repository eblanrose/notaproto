
#include "nap_rel.h"
#include "napc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef NAP_REL_DEBUG
#define REL_LOG(...) do { \
    fprintf(stderr, "[rel %d] ", (int)getpid()); \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); \
  } while (0)
#else
#define REL_LOG(...) do { } while (0)
#endif

int nap_rel_is_control(uint8_t type) {
    switch (type) {
    case NAP_MSG_CONNECT:
    case NAP_MSG_CONNECT_OK:
    case NAP_MSG_AUTH:
    case NAP_MSG_AUTH_OK:
    case NAP_MSG_AUTH_FAIL:
    case NAP_MSG_CLOSE:
    case NAP_MSG_PING:
    case NAP_MSG_PONG:
    case NAP_MSG_CUM:
        return 1;
    default:
        return 0;
    }
}

NapRel* nap_rel_create(size_t chunk) {
    NapRel *rel = calloc(1, sizeof(NapRel));
    if (!rel) return NULL;
    if (chunk < 16) chunk = 16;
    if (chunk > 65000) chunk = 65000;
    rel->chunk = chunk;
    return rel;
}

void nap_rel_destroy(NapRel *rel) {
    if (!rel) return;
    for (size_t i = 0; i < rel->inflight_n; i++) free(rel->inflight[i].data);
    for (size_t i = 0; i < rel->tx_queue_n; i++) free(rel->tx_queue[i].data);
    for (size_t i = 0; i < rel->rx_pending_n; i++) free(rel->rx_pending[i].data);
    free(rel->rx_acc);
    free(rel);
}

int nap_rel_has_room(NapRel *rel, size_t len) {
    if (!rel) return 0;
    if (rel->tx_queue_n >= NAP_REL_TX_QUEUE) return 0;
    if (rel->tx_queue_bytes + len + 4 > NAP_REL_TX_QUEUE_BYTES) return 0;
    return 1;
}

static uint8_t* build_packet(uint32_t session_id, uint16_t seq, uint8_t type,
                             const uint8_t *data, size_t len, size_t *out_len) {
    if (len > 65535 - sizeof(NAPHeader)) return NULL;

    size_t total = sizeof(NAPHeader) + len;
    uint8_t *p = malloc(total);
    if (!p) return NULL;

    NAPHeader *h = (NAPHeader*)p;
    memset(h, 0, sizeof(*h));
    h->magic = htonl(NAP_MAGIC);
    h->session_id = htonl(session_id);
    h->seq_num = htons(seq);
    h->msg_type = type;
    if (len > 0) memcpy(p + sizeof(NAPHeader), data, len);

    *out_len = total;
    return p;
}

static void rel_flush(NapRel *rel, nap_rel_tx_fn tx, void *user) {
    if (!rel || !tx) return;
    uint64_t now = napc_monotonic_ms();

    while (rel->inflight_n < NAP_REL_WINDOW && rel->tx_queue_n > 0) {
        NapRelQueued *m = &rel->tx_queue[0];
        int progressed = 0;

        while (m->sent < m->len && rel->inflight_n < NAP_REL_WINDOW) {
            size_t take = m->len - m->sent;
            if (take > rel->chunk) take = rel->chunk;
            if (rel->inflight_bytes + take > NAP_REL_MAX_INFLIGHT_BYTES) break;

            size_t total;
            uint16_t seq = (uint16_t)(m->seq_base + m->parts_sent);
            uint8_t *pkt = build_packet(m->sid, seq, m->type,
                                        m->data + m->sent, take, &total);
            if (!pkt) break;

            NapRelFrame f;
            memset(&f, 0, sizeof(f));
            f.data = pkt;
            f.len = total;
            f.seq = seq;
            f.type = m->type;
            f.last_tx_ms = now;
            f.rto_ms = NAP_REL_RTO_MS;

            tx(user, pkt, total);
            rel->inflight[rel->inflight_n++] = f;
            rel->inflight_bytes += take;
            m->sent += take;
            m->parts_sent++;
            progressed = 1;
            REL_LOG("TX seq=%u type=%u take=%zu off=%zu/%zu",
                    seq, m->type, take, m->sent, m->len);
        }

        if (m->sent >= m->len) {
            rel->tx_queue_bytes -= m->len;
            free(m->data);
            rel->tx_queue_n--;
            memmove(rel->tx_queue, rel->tx_queue + 1,
                    rel->tx_queue_n * sizeof(NapRelQueued));
            progressed = 1;
        }
        if (!progressed) break;
    }
}

int nap_rel_send(NapRel *rel, nap_rel_tx_fn tx, void *user,
                 uint32_t session_id, uint8_t type,
                 const uint8_t *data, size_t len) {
    if (!rel || !tx) return -1;
    if (len > NAP_REL_MAX_MSG) return -1;
    if (!nap_rel_has_room(rel, len)) return -1;
    if (len > 0 && !data) return -1;

    size_t flen = 4 + len;
    uint8_t *buf = malloc(flen);
    if (!buf) return -1;
    buf[0] = (uint8_t)(len >> 24);
    buf[1] = (uint8_t)(len >> 16);
    buf[2] = (uint8_t)(len >> 8);
    buf[3] = (uint8_t)(len);
    if (len) memcpy(buf + 4, data, len);

    NapRelQueued *m = &rel->tx_queue[rel->tx_queue_n++];
    m->data = buf;
    m->len = flen;
    m->sent = 0;
    m->seq_base = rel->tx_seq;
    m->parts_sent = 0;
    m->type = type;
    m->sid = session_id;
    rel->tx_seq = (uint16_t)(rel->tx_seq + (flen + rel->chunk - 1) / rel->chunk);
    rel->tx_queue_bytes += flen;

    rel_flush(rel, tx, user);
    return 0;
}

int nap_rel_tick(NapRel *rel, nap_rel_tx_fn tx, void *user) {
    if (!rel) return 0;
    uint64_t now = napc_monotonic_ms();

    rel_flush(rel, tx, user);

    if (rel->fast_retx && (now >= rel->fast_retx_until || rel->inflight_n == 0))
        rel->fast_retx = 0;
    if (rel->fast_retx) {
        NapRelFrame *gap = NULL;
        for (size_t i = 0; i < rel->inflight_n; i++) {
            if (rel->inflight[i].seq == rel->last_cum) {
                gap = &rel->inflight[i];
                break;
            }
        }
        if (!gap) {
            rel->fast_retx = 0;
        } else if (now - gap->last_tx_ms >= NAP_REL_FAST_RETX_MS) {
            tx(user, gap->data, gap->len);
            REL_LOG("FAST-RETX seq=%u cum=%u", gap->seq, rel->last_cum);
            gap->last_tx_ms = now;
        }
    }

    size_t w = 0;
    for (size_t i = 0; i < rel->inflight_n; i++) {
        NapRelFrame f = rel->inflight[i];

        if (now - f.last_tx_ms >= f.rto_ms) {
            if (f.retries >= NAP_REL_MAX_RETRIES) {
                free(f.data);
                rel->inflight_bytes -= f.len - sizeof(NAPHeader);
                rel->tx_dropped++;
                continue;
            }
            tx(user, f.data, f.len);
            REL_LOG("RETX seq=%u retries=%u expected-rto=%llu",
                    f.seq, f.retries + 1, (unsigned long long)f.rto_ms * 2);
            f.retries++;
            f.last_tx_ms = now;
            f.rto_ms *= 2;
            if (f.rto_ms > NAP_REL_RTO_MAX_MS) f.rto_ms = NAP_REL_RTO_MAX_MS;
        }
        rel->inflight[w++] = f;
    }
    rel->inflight_n = w;

    return (int)rel->inflight_n;
}

void nap_rel_on_ack(NapRel *rel, uint16_t cum_next) {
    if (!rel) return;

    if ((int16_t)(cum_next - rel->last_cum) <= 0) {
        rel->fast_retx = 1;
        rel->fast_retx_until = napc_monotonic_ms() + NAP_REL_FAST_RETX_WINDOW_MS;
    } else {
        rel->fast_retx = 0;
    }
    rel->last_cum = cum_next;

    REL_LOG("ACK cum=%u inflight=%zu", cum_next, rel->inflight_n);

    size_t w = 0;
    for (size_t i = 0; i < rel->inflight_n; i++) {
        NapRelFrame f = rel->inflight[i];
        if ((int16_t)(f.seq - cum_next) < 0) {
            rel->inflight_bytes -= f.len - sizeof(NAPHeader);
            free(f.data);
        } else {
            rel->inflight[w++] = f;
        }
    }
    rel->inflight_n = w;
}

static void rel_merged(NapRel *rel, uint8_t type, const uint8_t *data,
                       size_t len, nap_rel_deliver_fn deliver, void *user) {
    if (rel->rx_acc_have == 0) {
        if (len < 4) return;
        uint32_t total = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                         ((uint32_t)data[2] << 8)  | (uint32_t)data[3];
        if (total > NAP_REL_MAX_MSG) return;
        if (total > rel->rx_acc_cap) {
            uint8_t *p = realloc(rel->rx_acc, total ? total : 1);
            if (!p) return;
            rel->rx_acc = p;
            rel->rx_acc_cap = total ? total : 1;
        }
        rel->rx_acc_total = total;
        rel->rx_acc_type = type;
        size_t n = len - 4;
        if (n > total) n = total;
        if (n) memcpy(rel->rx_acc, data + 4, n);
        rel->rx_acc_have = n;
    } else {
        size_t room = rel->rx_acc_total - rel->rx_acc_have;
        size_t n = len < room ? len : room;
        if (n) memcpy(rel->rx_acc + rel->rx_acc_have, data, n);
        rel->rx_acc_have += n;
    }

    if (rel->rx_acc_have >= rel->rx_acc_total) {
        REL_LOG("MERGE type=%u total=%zu DELIVER", rel->rx_acc_type,
                rel->rx_acc_total);
        if (deliver) deliver(user, rel->rx_acc_type, rel->rx_acc,
                             rel->rx_acc_total);
        rel->rx_acc_have = 0;
        rel->rx_acc_total = 0;
    }
}

int nap_rel_recv(NapRel *rel, uint16_t seq, uint8_t type,
                 const uint8_t *data, size_t len,
                 nap_rel_deliver_fn deliver, void *user) {
    if (!rel) return -1;

    int16_t diff = (int16_t)(seq - rel->rx_expected);

    if (diff < 0) {
        REL_LOG("RX seq=%u expected=%u DUP", seq, rel->rx_expected);
        return 0;
    }

    if (diff == 0) {
        REL_LOG("RX seq=%u expected=%u DELIVER len=%zu type=%u b0=%02x%02x%02x%02x",
                seq, rel->rx_expected, len, type,
                len > 0 ? data[0] : 0, len > 1 ? data[1] : 0,
                len > 2 ? data[2] : 0, len > 3 ? data[3] : 0);
        rel_merged(rel, type, data, len, deliver, user);
        rel->rx_expected++;
        for (;;) {
            size_t hit = rel->rx_pending_n;
            for (size_t i = 0; i < rel->rx_pending_n; i++) {
                if (rel->rx_pending[i].seq == rel->rx_expected) { hit = i; break; }
            }
            if (hit == rel->rx_pending_n) break;

            NapRelFrame f = rel->rx_pending[hit];
            rel->rx_pending_n--;
            memmove(rel->rx_pending + hit, rel->rx_pending + hit + 1,
                    (rel->rx_pending_n - hit) * sizeof(NapRelFrame));
            rel->rx_expected++;

            REL_LOG("RX seq=%u expected=%u DRAIN-DELIVER len=%zu type=%u",
                    f.seq, (uint16_t)(rel->rx_expected - 1), f.len, f.type);
            rel_merged(rel, f.type, f.data, f.len, deliver, user);
            free(f.data);
        }
        return 1;
    }

    if (rel->rx_pending_n >= NAP_REL_RX_PENDING) {
        REL_LOG("RX seq=%u expected=%u PARK-FULL-DROP", seq, rel->rx_expected);
        return 1;
    }
    for (size_t i = 0; i < rel->rx_pending_n; i++) {
        if (rel->rx_pending[i].seq == seq) {
            REL_LOG("RX seq=%u expected=%u PARK-DUP", seq, rel->rx_expected);
            return 1;
        }
    }
    REL_LOG("RX seq=%u expected=%u PARK", seq, rel->rx_expected);

    uint8_t *copy = malloc(len ? len : 1);
    if (!copy) return -1;
    if (len) memcpy(copy, data, len);

    NapRelFrame *f = &rel->rx_pending[rel->rx_pending_n++];
    f->data = copy;
    f->len = len;
    f->seq = seq;
    f->type = type;
    f->last_tx_ms = 0;
    f->rto_ms = 0;
    f->retries = 0;
    return 1;
}
