
#include "nap.h"
#include "napc.h"
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

static void srv_send(NAPServerInternal *srv, NAPSession *sess, 
                     uint8_t type, const uint8_t *data, size_t len) {
    size_t total = sizeof(NAPHeader) + len;
    uint8_t packet[65535];
    
    NAPHeader *hdr = (NAPHeader*)packet;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(NAP_MAGIC);
    hdr->session_id = htonl(sess->session_id);
    hdr->seq_num = htons(sess->next_seq++);
    hdr->msg_type = type;
    
    if (data && len) memcpy(packet + sizeof(NAPHeader), data, len);
    
    
    ssize_t sent = sendto(srv->napc.socket_fd, packet, total, 0,
                         (struct sockaddr*)&sess->client_addr, sizeof(sess->client_addr));
    (void)sent;
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
            if (g_srv->sessions[i].state == NAP_SESSION_CLOSED) {
                sess = &g_srv->sessions[i];
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
    
    case NAP_MSG_DATA:
        if (sess && g_srv->on_data && len > sizeof(NAPHeader)) {
            g_srv->on_data(sid, 0, data + sizeof(NAPHeader), len - sizeof(NAPHeader));
        }
        break;
    
    case NAP_MSG_CLOSE:
        if (sess) {
            sess->state = NAP_SESSION_CLOSED;
            if (g_srv->on_disconnect) g_srv->on_disconnect(sid);
        }
        break;
    
    case NAP_MSG_PING:
        if (sess) srv_send(g_srv, sess, NAP_MSG_PONG, NULL, 0);
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
    
    isrv->on_connect = srv->on_connect;
    isrv->on_auth = srv->on_auth;
    isrv->on_data = srv->on_data;
    isrv->on_disconnect = srv->on_disconnect;
    
    srv->sessions = isrv->sessions;
    srv->max_sessions = max_sessions;
    
    g_srv = isrv;
    return 0;
}

int nap_server_poll(NAPServer *srv, int timeout_ms) {
    (void)srv;
    if (!g_srv) return -1;
    return napc_poll(&g_srv->napc, timeout_ms);
}

int nap_server_send(NAPServer *srv, uint32_t sid, uint8_t type,
                    const uint8_t *data, size_t len) {
    (void)srv;
    if (!g_srv) return -1;
    
    for (size_t i = 0; i < g_srv->max_sessions; i++) {
        if (g_srv->sessions[i].session_id == sid &&
            g_srv->sessions[i].state == NAP_SESSION_ACTIVE) {
            srv_send(g_srv, &g_srv->sessions[i], type, data, len);
            return 0;
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
    napc_close(&g_srv->napc);
    free(g_srv->sessions);
    free(g_srv);
    g_srv = NULL;
}
