
#include "nap.h"
#include "napc.h"
#include "nap_rel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define NAP_CLIENT_QUEUE_MAX   1024    /* inbound messages buffered for nap_client_recv */
#define NAP_CLIENT_RETRY_MS    300     /* handshake retransmit interval */
#define NAP_CLIENT_CONNECT_MS  6000    /* total CONNECT timeout: ~20 attempts,
                                          survives even 50% datagram loss
                                          (0.75^20 ~ 0.1% chance to exhaust) */
#define NAP_CLIENT_AUTH_MS     6000    /* total AUTH timeout: same reasoning -
                                          AUTH and its reply both cross the
                                          lossy path (0.25 success per round) */
#define NAP_CLIENT_RECV_MS     500     /* nap_client_recv wait (was SO_RCVTIMEO) */
#define NAP_CLIENT_KEEPALIVE_S 60      /* PING interval to keep the session alive */

typedef struct NapcQueuedMsg {
    struct NapcQueuedMsg *next;
    uint8_t  type;
    uint8_t *data;
    size_t   len;
} NapcQueuedMsg;

typedef struct {
    NapcQueuedMsg *head;
    NapcQueuedMsg *tail;
    size_t count;
} NapcMsgQueue;

static void queue_push(NapcMsgQueue *q, uint8_t type, const uint8_t *data, size_t len) {
    if (!q || q->count >= NAP_CLIENT_QUEUE_MAX) return;

    NapcQueuedMsg *m = malloc(sizeof(*m));
    if (!m) return;
    m->next = NULL;
    m->type = type;
    m->data = NULL;
    m->len = len;
    if (len > 0) {
        m->data = malloc(len);
        if (!m->data) { free(m); return; }
        memcpy(m->data, data, len);
    }
    if (q->tail) q->tail->next = m;
    else q->head = m;
    q->tail = m;
    q->count++;
}

static NapcQueuedMsg *queue_take_type(NapcMsgQueue *q, uint8_t type) {
    if (!q) return NULL;
    NapcQueuedMsg *prev = NULL, *cur = q->head;
    while (cur) {
        if (cur->type == type) {
            if (prev) prev->next = cur->next;
            else q->head = cur->next;
            if (q->tail == cur) q->tail = prev;
            cur->next = NULL;
            q->count--;
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }
    return NULL;
}

static NapcQueuedMsg *queue_pop(NapcMsgQueue *q) {
    if (!q || !q->head) return NULL;
    NapcQueuedMsg *m = q->head;
    q->head = m->next;
    if (!q->head) q->tail = NULL;
    m->next = NULL;
    q->count--;
    return m;
}

static void queue_destroy(NapcMsgQueue *q) {
    if (!q) return;
    NapcQueuedMsg *m;
    while ((m = queue_pop(q)) != NULL) {
        free(m->data);
        free(m);
    }
    free(q);
}

static int cli_send_msg(NAPClient *cli, uint8_t type,
                        const uint8_t *data, size_t len) {
    if (!cli || !cli->napc) return -1;
    if (len > 65535 - sizeof(NAPHeader)) return -1;

    uint8_t packet[65535];
    NAPHeader *hdr = (NAPHeader*)packet;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(NAP_MAGIC);
    hdr->session_id = htonl(cli->session_id);
    hdr->seq_num = htons(cli->next_seq++);
    hdr->msg_type = type;
    if (data && len) memcpy(packet + sizeof(NAPHeader), data, len);

    cli->last_activity = time(NULL);
    return napc_send(cli->napc, packet, sizeof(NAPHeader) + len,
                     &cli->server_addr) < 0 ? -1 : 0;
}

static int cli_raw_tx(void *user, const uint8_t *packet, size_t len) {
    NAPClient *cli = user;
    return napc_send(cli->napc, packet, len, &cli->server_addr) < 0 ? -1 : 0;
}

static NapRel* cli_rel_new(NAPClient *cli) {
    if (!cli || !cli->napc) return NULL;
    return nap_rel_create(napc_single_max(cli->napc) - sizeof(NAPHeader));
}

static void cli_reliable_deliver(void *user, uint8_t type,
                                 const uint8_t *data, size_t len) {
    NAPClient *cli = user;
    queue_push(cli->recv_queue, type, data, len);
}

static void cli_recv_cb(NapcCtx *ctx, const uint8_t *data, size_t len,
                        struct sockaddr_in *src, uint32_t ident) {
    (void)src; (void)ident;
    NAPClient *cli = (NAPClient*)ctx->user_data;
    if (!cli || !cli->recv_queue) return;
    if (len < sizeof(NAPHeader)) return;

    const NAPHeader *hdr = (const NAPHeader*)data;
    if (hdr->magic != htonl(NAP_MAGIC)) return;
    if (ntohl(hdr->session_id) != cli->session_id) return;

    cli->last_activity = time(NULL);

    if (hdr->msg_type == NAP_MSG_CUM) {
        if (cli->rel && len >= sizeof(NAPHeader) + 2) {
            const uint8_t *p = data + sizeof(NAPHeader);
            nap_rel_on_ack(cli->rel, (uint16_t)(((uint16_t)p[0] << 8) | p[1]));
        }
        return;
    }

    if (hdr->msg_type == NAP_MSG_PING) {
        cli_send_msg(cli, NAP_MSG_PONG, NULL, 0);
        return;
    }
    if (hdr->msg_type == NAP_MSG_PONG) return;

    if (hdr->msg_type == NAP_MSG_CONNECT_OK && cli->state != NAP_SESSION_NEW)
        return;
    if ((hdr->msg_type == NAP_MSG_AUTH_OK || hdr->msg_type == NAP_MSG_AUTH_FAIL) &&
        cli->state != NAP_SESSION_AUTHENTICATING)
        return;

    if (!nap_rel_is_control(hdr->msg_type)) {
        if (!cli->rel) cli->rel = cli_rel_new(cli);
        if (cli->rel) {
            nap_rel_recv(cli->rel, ntohs(hdr->seq_num), hdr->msg_type,
                         data + sizeof(NAPHeader),
                         len - sizeof(NAPHeader),
                         cli_reliable_deliver, cli);
            cli->cum_dirty = 1;
        }
        return;
    }

    queue_push(cli->recv_queue, hdr->msg_type,
               data + sizeof(NAPHeader), len - sizeof(NAPHeader));
}

static void cli_post_drain(NapcCtx *ctx) {
    NAPClient *cli = (NAPClient*)ctx->user_data;
    if (!cli || !cli->cum_dirty || !cli->rel) return;
    cli->cum_dirty = 0;
    uint16_t cum = cli->rel->rx_expected;
    uint8_t ack[2] = { (uint8_t)(cum >> 8), (uint8_t)(cum & 0xFF) };
    cli_send_msg(cli, NAP_MSG_CUM, ack, sizeof(ack));
}

static void queue_flush_type(NapcMsgQueue *q, uint8_t type) {
    NapcQueuedMsg *m;
    while ((m = queue_take_type(q, type)) != NULL) {
        free(m->data);
        free(m);
    }
}

static void cli_keepalive(NAPClient *cli) {
    if (!cli->napc || cli->state != NAP_SESSION_ACTIVE) return;
    if (time(NULL) - cli->last_activity >= NAP_CLIENT_KEEPALIVE_S)
        cli_send_msg(cli, NAP_MSG_PING, NULL, 0);
}

static void cli_teardown(NAPClient *cli) {
    if (cli->napc) {
        napc_close(cli->napc);
        free(cli->napc);
        cli->napc = NULL;
    }
    queue_destroy(cli->recv_queue);
    cli->recv_queue = NULL;
    nap_rel_destroy(cli->rel);
    cli->rel = NULL;
    cli->fd = -1;
}

int nap_client_init(NAPClient *cli) {
    if (!cli) return -1;
    memset(cli, 0, sizeof(NAPClient));
    cli->session_id = napc_generate_ident();
    cli->state = NAP_SESSION_NEW;
    cli->fd = -1;
    return 0;
}

int nap_client_set_mds(NAPClient *cli, uint16_t mds) {
    if (!cli || mds < 64) return -1;
    if (cli->napc) cli->napc->local_mds = mds;
    cli->mds = mds;
    return 0;
}

int nap_client_connect(NAPClient *cli, const char *host, uint16_t port) {
    if (!cli || cli->state != NAP_SESSION_NEW || !host) return -1;

    NapcCtx *ctx = calloc(1, sizeof(NapcCtx));
    if (!ctx) return -1;
    if (napc_init(ctx, 0) < 0) {
        free(ctx);
        return -1;
    }
    if (cli->mds) ctx->local_mds = cli->mds;

    NapcMsgQueue *q = calloc(1, sizeof(NapcMsgQueue));
    if (!q) {
        napc_close(ctx);
        free(ctx);
        return -1;
    }

    cli->napc = ctx;
    cli->recv_queue = q;
    cli->rel = cli_rel_new(cli);
    if (!cli->rel) {
        cli_teardown(cli);
        return -1;
    }
    ctx->user_data = cli;
    napc_set_recv_cb(ctx, cli_recv_cb);
    ctx->post_drain = cli_post_drain;
    cli->fd = ctx->socket_fd;

    memset(&cli->server_addr, 0, sizeof(cli->server_addr));
    cli->server_addr.sin_family = AF_INET;
    cli->server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &cli->server_addr.sin_addr) != 1) {
        cli_teardown(cli);
        return -1;
    }

    uint64_t deadline = napc_monotonic_ms() + NAP_CLIENT_CONNECT_MS;
    uint64_t next_tx = 0;

    for (;;) {
        uint64_t now = napc_monotonic_ms();
        if (now >= deadline) break;

        if (now >= next_tx) {
            cli_send_msg(cli, NAP_MSG_CONNECT, NULL, 0);
            next_tx = now + NAP_CLIENT_RETRY_MS;
        }

        napc_poll(ctx, 20);

        NapcQueuedMsg *m = queue_take_type(q, NAP_MSG_CONNECT_OK);
        if (m) {
            free(m->data);
            free(m);
            while ((m = queue_take_type(q, NAP_MSG_CONNECT_OK)) != NULL) {
                free(m->data);
                free(m);
            }
            cli->state = NAP_SESSION_AUTHENTICATING;
            return 0;
        }
    }

    cli_teardown(cli);
    return -1;
}


int nap_client_auth(NAPClient *cli, const char *username, const char *password) {
    if (!cli || cli->state != NAP_SESSION_AUTHENTICATING || !cli->napc) return -1;
    if (!username || !password) return -1;

    char creds[512];
    snprintf(creds, sizeof(creds), "%s\n%s", username, password);

    uint64_t deadline = napc_monotonic_ms() + NAP_CLIENT_AUTH_MS;
    uint64_t next_tx = 0;

    for (;;) {
        uint64_t now = napc_monotonic_ms();
        if (now >= deadline) break;

        if (now >= next_tx) {
            cli_send_msg(cli, NAP_MSG_AUTH, (const uint8_t*)creds, strlen(creds));
            next_tx = now + NAP_CLIENT_RETRY_MS;
        }

        napc_poll(cli->napc, 20);

        NapcMsgQueue *q = (NapcMsgQueue*)cli->recv_queue;

        NapcQueuedMsg *ok = queue_take_type(q, NAP_MSG_AUTH_OK);
        if (ok) {
            free(ok->data);
            free(ok);
            queue_flush_type(q, NAP_MSG_AUTH_OK);
            queue_flush_type(q, NAP_MSG_AUTH_FAIL);
            cli->state = NAP_SESSION_ACTIVE;
            return 0;
        }
        NapcQueuedMsg *fail = queue_take_type(q, NAP_MSG_AUTH_FAIL);
        if (fail) {
            free(fail->data);
            free(fail);
            queue_flush_type(q, NAP_MSG_AUTH_OK);
            queue_flush_type(q, NAP_MSG_AUTH_FAIL);
            return -1;
        }
    }

    {
        NapcMsgQueue *q = (NapcMsgQueue*)cli->recv_queue;
        queue_flush_type(q, NAP_MSG_AUTH_OK);
        queue_flush_type(q, NAP_MSG_AUTH_FAIL);
    }
    return -1;
}

int nap_client_send_data(NAPClient *cli, const uint8_t *data, size_t len) {
    if (!cli || cli->state != NAP_SESSION_ACTIVE || cli->fd < 0) return -1;

    if (cli->rel) nap_rel_tick(cli->rel, cli_raw_tx, cli);
    cli_keepalive(cli);

    if (!cli->rel) cli->rel = cli_rel_new(cli);
    if (!cli->rel) return -1;
    return nap_rel_send(cli->rel, cli_raw_tx, cli, cli->session_id,
                        NAP_MSG_DATA, data, len);
}

int nap_client_recv(NAPClient *cli, uint8_t *type, uint8_t **data, size_t *len) {
    if (!cli || !cli->napc || cli->fd < 0 || !type || !data || !len) return -1;

    *data = NULL;
    *len = 0;

    NapcMsgQueue *q = (NapcMsgQueue*)cli->recv_queue;
    cli_keepalive(cli);
    if (cli->rel) nap_rel_tick(cli->rel, cli_raw_tx, cli);

    uint64_t deadline = napc_monotonic_ms() + NAP_CLIENT_RECV_MS;
    while (!q->head) {
        uint64_t now = napc_monotonic_ms();
        if (now >= deadline) return -1;
        int slice = (int)(deadline - now);
        if (cli->rel && nap_rel_tick(cli->rel, cli_raw_tx, cli) > 0 && slice > 50)
            slice = 50;
        napc_poll(cli->napc, slice);
    }

    NapcQueuedMsg *m = queue_pop(q);
    *type = m->type;
    *data = m->data;
    *len = m->len;
    free(m);
    return 0;
}

int nap_client_wait_acked(NAPClient *cli, int timeout_ms) {
    if (!cli || cli->fd < 0) return -1;
    if (!cli->rel) return 0;

    uint64_t deadline = napc_monotonic_ms() + (uint64_t)(timeout_ms > 0 ? timeout_ms : 0);
    cli_keepalive(cli);

    for (;;) {
        if (cli->rel->inflight_n == 0 && cli->rel->tx_queue_n == 0)
            return 0;

        uint64_t now = napc_monotonic_ms();
        if (now >= deadline) return -1;

        nap_rel_tick(cli->rel, cli_raw_tx, cli);
        int slice = (int)(deadline - now);
        if (slice > 50) slice = 50;
        napc_poll(cli->napc, slice);
    }
}

int nap_client_wait_space(NAPClient *cli, size_t len, int timeout_ms) {
    if (!cli || cli->fd < 0) return -1;
    if (!cli->rel) return 0;

    uint64_t deadline = napc_monotonic_ms() + (uint64_t)(timeout_ms > 0 ? timeout_ms : 0);
    cli_keepalive(cli);

    for (;;) {
        if (nap_rel_has_room(cli->rel, len))
            return 0;

        uint64_t now = napc_monotonic_ms();
        if (now >= deadline) return -1;

        nap_rel_tick(cli->rel, cli_raw_tx, cli);
        int slice = (int)(deadline - now);
        if (slice > 50) slice = 50;
        napc_poll(cli->napc, slice);
    }
}

int nap_client_close(NAPClient *cli) {
    if (!cli) return -1;
    if (cli->napc) {
        cli_send_msg(cli, NAP_MSG_CLOSE, NULL, 0);
    }
    cli_teardown(cli);
    cli->state = NAP_SESSION_CLOSED;
    return 0;
}
