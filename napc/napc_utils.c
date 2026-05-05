
#include "napc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>



uint32_t napc_crc32c(const uint8_t *data, size_t len) {
    static uint32_t table[256];
    static int initialized = 0;
    
    if (!initialized) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78 : 0);
            table[i] = crc;
        }
        initialized = 1;
    }
    
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ table[(crc ^ data[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}



uint32_t napc_ocs_compute(const uint8_t *surplus, size_t surplus_len) {
    uint8_t temp[65535];
    memcpy(temp, surplus, surplus_len);
    temp[0] = temp[1] = temp[2] = temp[3] = 0;
    return napc_crc32c(temp, surplus_len);
}



uint32_t napc_generate_ident(void) {
    static uint32_t counter = 0;
    uint32_t id;
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        fread(&id, sizeof(id), 1, f);
        fclose(f);
    } else {
        id = (uint32_t)time(NULL);
    }
    return id ^ (uint32_t)(++counter) ^ (uint32_t)(getpid() << 16) ?: 1;
}

uint64_t napc_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
