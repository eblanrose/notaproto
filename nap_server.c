
#include "nap.h"
#include "napc.h"
#include "nap_rel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

typedef struct {
    NapcCtx napc;
    NAPSession *sessions;
    size_t max_sessions;
    
    int (*on_auth)(uint32_t sid, const char *user, const char *pass);
    void (*on_connect)(uint32_t sid, struct sockaddr_in *addr);
    void (*on_data)(uint32_t sid, uint8_t ch, const uint8_t *data, size_t len);
    void (*on_disconnect)(uint32_t sid);
} NAPServerInternal;

static NAPServerInternal *g_srv = NULL;

#define NAP_SESSION_IDLE_TIMEOUT 1800

static int srv_send(NAPServerInternal *srv, NAPSession *sess, 
                     uint8_t type, const uint8_t *data, size_t len) {
    if (len > 65535 - sizeof(NAPHeader)) return -1;

    uint8_t packet[65535];
    NAPHeader *hdr = (NAPHeader*)packet;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(NAP_MAGIC);
    hdr->session_id = htonl(sess->session_id);
    hdr->seq_num = htons(sess->next_seq++);
    hdr->msg_type = type;
    
    if (data && len) memcpy(packet + sizeof(NAPHeader), data, len);

    return napc_send(&srv->napc, packet, sizeof(NAPHeader) + len,
                     &sess->client_addr) < 0 ? -1 : 0;
}

static int srv_raw_tx(void *user, const uint8_t *packet, size_t len) {
    NAPSession *sess = user;
    return napc_send(&g_srv->napc, packet, len,
                     &sess->client_addr) < 0 ? -1 : 0;
}

static NapRel* srv_rel_new(void) {
    if (!g_srv) return NULL;
    return nap_rel_create(napc_single_max(&g_srv->napc) - sizeof(NAPHeader));
}

static void srv_reliable_deliver(void *user, uint8_t type,
                                 const uint8_t *data, size_t len) {
    NAPSession *sess = user;
    if (type == NAP_MSG_DATA && g_srv->on_data && len > 0)
        g_srv->on_data(sess->session_id, 0, data, len);
}

static void srv_send_cum(NAPSession *sess) {
    if (!sess->rel) return;
    uint16_t cum = sess->rel->rx_expected;
    uint8_t ack[2] = { (uint8_t)(cum >> 8), (uint8_t)(cum & 0xFF) };
    srv_send(g_srv, sess, NAP_MSG_CUM, ack, sizeof(ack));
}

static void srv_post_drain(NapcCtx *ctx) {
    (void)ctx;
    if (!g_srv) return;
    for (size_t i = 0; i < g_srv->max_sessions; i++) {
        NAPSession *s = &g_srv->sessions[i];
        if (s->state == NAP_SESSION_ACTIVE && s->rel && s->cum_dirty) {
            s->cum_dirty = 0;
            srv_send_cum(s);
        }
    }
}

static void napc_callback(NapcCtx *ctx, const uint8_t *data, size_t len,
                          struct sockaddr_in *src, uint32_t ident) {
    (void)ctx; (void)ident;
    if (!g_srv || len < sizeof(NAPHeader)) return;
    
    NAPHeader *hdr = (NAPHeader*)data;
    if (hdr->magic != htonl(NAP_MAGIC)) return;
    
    uint32_t sid = ntohl(hdr->session_id);
    
    NAPSession *sess = NULL;
    for (size_t i = 0; i < g_srv->max_sessions; i++) {
        if (g_srv->sessions[i].state == NAP_SESSION_ACTIVE &&
            g_srv->sessions[i].session_id == sid) {
            sess = &g_srv->sessions[i];
            break;
        }
    }
    
    switch (hdr->msg_type) {
    case NAP_MSG_CONNECT:
        for (size_t i = 0; i < g_srv->max_sessions; i++) {
            NAPSession *s = &g_srv->sessions[i];
            if (s->state != NAP_SESSION_CLOSED && s->session_id == sid) {
                s->client_addr = *src;
                s->last_activity = time(NULL);
                srv_send(g_srv, s, NAP_MSG_CONNECT_OK, NULL, 0);
                return;
            }
        }
        for (size_t i = 0; i < g_srv->max_sessions; i++) {
            if (g_srv->sessions[i].state == NAP_SESSION_CLOSED) {
                sess = &g_srv->sessions[i];
                nap_rel_destroy(sess->rel);
                memset(sess, 0, sizeof(NAPSession));
                sess->session_id = sid;
                sess->state = NAP_SESSION_ACTIVE;
                sess->client_addr = *src;
                sess->created_at = time(NULL);
                sess->last_activity = time(NULL);
                
                srv_send(g_srv, sess, NAP_MSG_CONNECT_OK, NULL, 0);
                if (g_srv->on_connect) g_srv->on_connect(sid, src);
                return;
            }
        }
        break;
    
    case NAP_MSG_AUTH:
        if (sess && len > sizeof(NAPHeader)) {
            const uint8_t *payload = data + sizeof(NAPHeader);
            size_t plen = len - sizeof(NAPHeader);
            char *creds = strndup((char*)payload, plen);
            if (creds) {
                char *user = creds;
                char *pass = strchr(creds, '\n');
                if (pass) {
                    *pass++ = '\0';
                    if (g_srv->on_auth) {
                        int result = g_srv->on_auth(sid, user, pass);
                       srv_send(g_srv, sess, result == 0 ? NAP_MSG_AUTH_OK : NAP_MSG_AUTH_FAIL, NULL, 0);
                    } else {
                        srv_send(g_srv, sess, NAP_MSG_AUTH_OK, NULL, 0);
                    }
                }
                free(creds);
            }
        }
        break;
    
    case NAP_MSG_CUM:
        if (sess && sess->rel && len >= sizeof(NAPHeader) + 2) {
            const uint8_t *p = data + sizeof(NAPHeader);
            nap_rel_on_ack(sess->rel, (uint16_t)(((uint16_t)p[0] << 8) | p[1]));
        }
        break;
    
    case NAP_MSG_CLOSE:
        if (sess) {
            nap_rel_destroy(sess->rel);
            sess->rel = NULL;
            sess->state = NAP_SESSION_CLOSED;
            if (g_srv->on_disconnect) g_srv->on_disconnect(sid);
        }
        break;
    
    case NAP_MSG_PING:
        if (sess) srv_send(g_srv, sess, NAP_MSG_PONG, NULL, 0);
        break;
    
    default:
        if (sess && !nap_rel_is_control(hdr->msg_type)) {
            if (!sess->rel) sess->rel = srv_rel_new();
            if (sess->rel) {
                nap_rel_recv(sess->rel, ntohs(hdr->seq_num), hdr->msg_type,
                             data + sizeof(NAPHeader),
                             len - sizeof(NAPHeader),
                             srv_reliable_deliver, sess);
                sess->cum_dirty = 1;
            }
        }
        break;
    }
    
    if (sess) {
        sess->last_recv_seq = ntohs(hdr->seq_num);
        sess->last_activity = time(NULL);
    }
}

int nap_server_init(NAPServer *srv, uint16_t port, size_t max_sessions) {
    if (!srv) return -1;
    
    NAPServerInternal *isrv = calloc(1, sizeof(NAPServerInternal));
    if (!isrv) return -1;
    
    isrv->max_sessions = max_sessions;
    isrv->sessions = calloc(max_sessions, sizeof(NAPSession));
    if (!isrv->sessions) { free(isrv); return -1; }
    
    if (napc_init(&isrv->napc, port) < 0) {
        free(isrv->sessions);
        free(isrv);
        return -1;
    }
    
    napc_set_recv_cb(&isrv->napc, napc_callback);
    isrv->napc.post_drain = srv_post_drain;
    
    isrv->on_connect = srv->on_connect;
    isrv->on_auth = srv->on_auth;
    isrv->on_data = srv->on_data;
    isrv->on_disconnect = srv->on_disconnect;
    
    srv->sessions = isrv->sessions;
    srv->max_sessions = max_sessions;
    
    g_srv = isrv;
    return 0;
}

int nap_server_set_mds(NAPServer *srv, uint16_t mds) {
    (void)srv;
    if (!g_srv || mds < 64) return -1;
    g_srv->napc.local_mds = mds;
    return 0;
}

int nap_server_poll(NAPServer *srv, int timeout_ms) {
    (void)srv;
    if (!g_srv) return -1;

    int unacked = 0;
    for (size_t i = 0; i < g_srv->max_sessions; i++) {
        NAPSession *s = &g_srv->sessions[i];
        if (s->state == NAP_SESSION_ACTIVE && s->rel)
            unacked += nap_rel_tick(s->rel, srv_raw_tx, s);
    }
    int poll_ms = timeout_ms;
    if (unacked > 0 && (poll_ms < 0 || poll_ms > 50)) poll_ms = 50;

    int rc = napc_poll(&g_srv->napc, poll_ms);

    time_t now = time(NULL);
    for (size_t i = 0; i < g_srv->max_sessions; i++) {
        NAPSession *s = &g_srv->sessions[i];
        if (s->state == NAP_SESSION_ACTIVE &&
            now - s->last_activity > NAP_SESSION_IDLE_TIMEOUT) {
            nap_rel_destroy(s->rel);
            s->rel = NULL;
            s->state = NAP_SESSION_CLOSED;
            if (g_srv->on_disconnect) g_srv->on_disconnect(s->session_id);
        }
    }

    return rc;
}

int nap_server_send(NAPServer *srv, uint32_t sid, uint8_t type,
                    const uint8_t *data, size_t len) {
    (void)srv;
    if (!g_srv) return -1;

    for (size_t i = 0; i < g_srv->max_sessions; i++) {
        if (g_srv->sessions[i].session_id == sid &&
            g_srv->sessions[i].state == NAP_SESSION_ACTIVE) {
            NAPSession *s = &g_srv->sessions[i];

            if (nap_rel_is_control(type))
                return srv_send(g_srv, s, type, data, len);

            if (len > NAP_REL_MAX_MSG) return -1;
            if (!s->rel) s->rel = srv_rel_new();
            if (!s->rel) return -1;
            return nap_rel_send(s->rel, srv_raw_tx, s, s->session_id,
                                type, data, len);
        }
    }
    return -1;
}

int nap_server_close_session(NAPServer *srv, uint32_t sid) {
    return nap_server_send(srv, sid, NAP_MSG_CLOSE, NULL, 0);
}

void nap_server_cleanup(NAPServer *srv) {
    (void)srv;
    if (!g_srv) return;
    for (size_t i = 0; i < g_srv->max_sessions; i++)
        nap_rel_destroy(g_srv->sessions[i].rel);
    napc_close(&g_srv->napc);
    free(g_srv->sessions);
    free(g_srv);
    g_srv = NULL;
}
