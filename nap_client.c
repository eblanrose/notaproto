
#include "nap.h"
#include "napc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

int nap_client_init(NAPClient *cli) {
    if (!cli) return -1;
    memset(cli, 0, sizeof(NAPClient));
    cli->session_id = napc_generate_ident();
    cli->state = NAP_SESSION_NEW;
    cli->fd = -1;
    return 0;
}

static int cli_send_raw(int fd, struct sockaddr_in *dst, uint32_t sid, 
                        uint16_t *seq, uint8_t type, const uint8_t *data, size_t len) {
    size_t total = sizeof(NAPHeader) + len;
    uint8_t packet[65535];
    
    NAPHeader *hdr = (NAPHeader*)packet;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(NAP_MAGIC);
    hdr->session_id = htonl(sid);
    hdr->seq_num = htons((*seq)++);
    hdr->msg_type = type;
    
    if (data && len) memcpy(packet + sizeof(NAPHeader), data, len);
    
    ssize_t sent = sendto(fd, packet, total, 0, (struct sockaddr*)dst, sizeof(*dst));
    return (sent > 0) ? 0 : -1;
}

int nap_client_connect(NAPClient *cli, const char *host, uint16_t port) {
    if (!cli || cli->state != NAP_SESSION_NEW) return -1;
    
    cli->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (cli->fd < 0) return -1;
    
    struct timeval tv = {2, 0};
    setsockopt(cli->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    cli->server_addr.sin_family = AF_INET;
    cli->server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &cli->server_addr.sin_addr);
    
    cli_send_raw(cli->fd, &cli->server_addr, cli->session_id, 
                 &cli->next_seq, NAP_MSG_CONNECT, NULL, 0);
    
    uint8_t buf[65535];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(cli->fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
    
    if (n < (ssize_t)sizeof(NAPHeader)) goto fail;
    
    NAPHeader *resp = (NAPHeader*)buf;
    if (resp->magic != htonl(NAP_MAGIC)) goto fail;
    if (resp->session_id != htonl(cli->session_id)) goto fail;
    if (resp->msg_type != NAP_MSG_CONNECT_OK) goto fail;
    
    cli->state = NAP_SESSION_AUTHENTICATING;
    tv.tv_sec = 0; tv.tv_usec = 500000;
    setsockopt(cli->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
    
fail:
    close(cli->fd);
    cli->fd = -1;
    return -1;
}


int nap_client_auth(NAPClient *cli, const char *username, const char *password) {
    if (!cli || cli->state != NAP_SESSION_AUTHENTICATING) return -1;
    
    char creds[512];
    snprintf(creds, sizeof(creds), "%s\n%s", username, password);
    
    cli_send_raw(cli->fd, &cli->server_addr, cli->session_id,
                 &cli->next_seq, NAP_MSG_AUTH, (uint8_t*)creds, strlen(creds));
    
    uint8_t buf[65535];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(cli->fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
    
    if (n >= (ssize_t)sizeof(NAPHeader)) {
        NAPHeader *resp = (NAPHeader*)buf;
        if (resp->magic == htonl(NAP_MAGIC) && resp->msg_type == NAP_MSG_AUTH_OK) {
            cli->state = NAP_SESSION_ACTIVE;
            return 0;
        }
    }
    
    return -1;
}

int nap_client_send_data(NAPClient *cli, const uint8_t *data, size_t len) {
    if (!cli || cli->state != NAP_SESSION_ACTIVE || cli->fd < 0) return -1;
    return cli_send_raw(cli->fd, &cli->server_addr, cli->session_id,
                        &cli->next_seq, NAP_MSG_DATA, data, len);
}

int nap_client_recv(NAPClient *cli, uint8_t *type, uint8_t **data, size_t *len) {
    if (!cli || cli->fd < 0) return -1;
    
    *data = NULL;
    *len = 0;
    
    uint8_t buf[65535];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(cli->fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
    
    if (n < (ssize_t)sizeof(NAPHeader)) return -1;
    NAPHeader *hdr = (NAPHeader*)buf;
    if (hdr->magic != htonl(NAP_MAGIC)) return -1;
    
    *type = hdr->msg_type;
    size_t plen = n - sizeof(NAPHeader);
    
    if (plen > 0) {
        *data = malloc(plen);
        if (!*data) return -1;
        memcpy(*data, buf + sizeof(NAPHeader), plen);
        *len = plen;
    }
    return 0;
}

int nap_client_close(NAPClient *cli) {
    if (!cli) return -1;
    if (cli->fd >= 0) {
        cli_send_raw(cli->fd, &cli->server_addr, cli->session_id,
                     &cli->next_seq, NAP_MSG_CLOSE, NULL, 0);
        close(cli->fd);
        cli->fd = -1;
    }
    cli->state = NAP_SESSION_CLOSED;
    return 0;
}
