
#ifndef NAP_H
#define NAP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NAP_MAGIC        0x6E617000
#define NAP_HEADER_SIZE  12
#define NAP_MAX_CHANNELS 8

typedef enum {
    NAP_MSG_CONNECT    = 0x01,
    NAP_MSG_CONNECT_OK = 0x02,
    NAP_MSG_AUTH       = 0x03,
    NAP_MSG_AUTH_OK    = 0x04,
    NAP_MSG_AUTH_FAIL  = 0x05,
    NAP_MSG_DATA       = 0x06,
    NAP_MSG_CHANNEL_OPEN  = 0x07,
    NAP_MSG_CHANNEL_CLOSE = 0x08,
    NAP_MSG_CLOSE      = 0x09,
    NAP_MSG_PING       = 0x0A,
    NAP_MSG_PONG       = 0x0B,
} NAPMessageType;

typedef enum {
    NAP_CHANNEL_SHELL       = 0x01,
    NAP_CHANNEL_TUNNEL_TCP  = 0x02,
    NAP_CHANNEL_TUNNEL_UDP  = 0x03,
    NAP_CHANNEL_FILE        = 0x04,
} NAPChannelType;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t session_id;
    uint16_t seq_num;
    uint8_t  msg_type;
    uint8_t  flags;
} NAPHeader;

typedef struct __attribute__((packed)) {
    uint8_t  channel_type;
    uint8_t  channel_id;
    uint16_t reserved;
} NAPChannelHeader;

typedef enum {
    NAP_SESSION_CLOSED = 0,
    NAP_SESSION_NEW,
    NAP_SESSION_AUTHENTICATING,
    NAP_SESSION_ACTIVE,
    NAP_SESSION_CLOSING
} NAPSessionState;

typedef struct {
    uint32_t session_id;
    NAPSessionState state;
    struct sockaddr_in server_addr;
    int fd;
    uint16_t next_seq;
    time_t last_activity;
    uint32_t bytes_sent;
    uint32_t bytes_recv;
} NAPClient;

typedef struct {
    uint32_t session_id;
    NAPSessionState state;
    struct sockaddr_in client_addr;
    uint16_t next_seq;
    uint16_t last_recv_seq;
    time_t last_activity;
    time_t created_at;
    uint32_t bytes_sent;
    uint32_t bytes_recv;
    void *user_data;
} NAPSession;

typedef struct {
    NAPSession *sessions;
    size_t max_sessions;
    
    void (*on_connect)(uint32_t session_id, struct sockaddr_in *addr);
    int  (*on_auth)(uint32_t session_id, const char *username, const char *password);
    void (*on_data)(uint32_t session_id, uint8_t channel_id, const uint8_t *data, size_t len);
    void (*on_disconnect)(uint32_t session_id);
} NAPServer;

int nap_server_init(NAPServer *srv, uint16_t port, size_t max_sessions);
int nap_server_poll(NAPServer *srv, int timeout_ms);
int nap_server_send(NAPServer *srv, uint32_t session_id, uint8_t msg_type,
                    const uint8_t *data, size_t len);
int nap_server_close_session(NAPServer *srv, uint32_t session_id);
void nap_server_cleanup(NAPServer *srv);

int nap_client_init(NAPClient *cli);
int nap_client_connect(NAPClient *cli, const char *host, uint16_t port);
int nap_client_auth(NAPClient *cli, const char *username, const char *password);
int nap_client_send_data(NAPClient *cli, const uint8_t *data, size_t len);
int nap_client_recv(NAPClient *cli, uint8_t *type, uint8_t **data, size_t *len);
int nap_client_close(NAPClient *cli);

#endif
