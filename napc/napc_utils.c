#include <unistd.h>
#include "napc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#if defined(__x86_64__) || defined(__i386__)
#include <nmmintrin.h>      /* SSE4.2 CRC32C */
#endif
#if defined(__linux__)
#include <sys/random.h>
#endif


static uint32_t crc32c_table[8][256];
static int crc32c_initialized = 0;

static void crc32c_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
        crc32c_table[0][i] = crc;
    }
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = crc32c_table[0][i];
        for (int k = 1; k < 8; k++) {
            crc = crc32c_table[0][crc & 0xFF] ^ (crc >> 8);
            crc32c_table[k][i] = crc;
        }
    }
    crc32c_initialized = 1;
}

#if defined(__x86_64__) || defined(__i386__)
__attribute__((target("sse4.2")))
static uint32_t crc32c_hw_update(uint32_t crc, const uint8_t *data, size_t len) {
    while (len && ((uintptr_t)data & 7)) {
        crc = _mm_crc32_u8(crc, *data++);
        len--;
    }
#ifdef __x86_64__
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, data, 8);
        crc = (uint32_t)_mm_crc32_u64(crc, v);
        data += 8;
        len -= 8;
    }
#endif
    while (len >= 4) {
        uint32_t v;
        memcpy(&v, data, 4);
        crc = _mm_crc32_u32(crc, v);
        data += 4;
        len -= 4;
    }
    while (len--) {
        crc = _mm_crc32_u8(crc, *data++);
    }
    return crc;
}

static int crc32c_have_hw(void) {
    static int cached = -1;
    if (cached < 0) {
#ifdef __GNUC__
        __builtin_cpu_init();
        cached = __builtin_cpu_supports("sse4.2") ? 1 : 0;
#else
        cached = 0;
#endif
    }
    return cached;
}
#else
static int crc32c_have_hw(void) { return 0; }
#endif

static uint32_t crc32c_update(uint32_t crc, const uint8_t *data, size_t len) {
    if (!crc32c_initialized) crc32c_init();
    if (crc32c_have_hw()) return crc32c_hw_update(crc, data, len);

    while (len >= 8) {
        uint32_t lo, hi;
        memcpy(&lo, data, 4);
        memcpy(&hi, data + 4, 4);
        lo ^= crc;
        crc = crc32c_table[7][lo & 0xFF] ^
              crc32c_table[6][(lo >> 8) & 0xFF] ^
              crc32c_table[5][(lo >> 16) & 0xFF] ^
              crc32c_table[4][(lo >> 24) & 0xFF] ^
              crc32c_table[3][hi & 0xFF] ^
              crc32c_table[2][(hi >> 8) & 0xFF] ^
              crc32c_table[1][(hi >> 16) & 0xFF] ^
              crc32c_table[0][(hi >> 24) & 0xFF];
        data += 8;
        len -= 8;
    }
    while (len--) {
        crc = (crc >> 8) ^ crc32c_table[0][(crc ^ *data++) & 0xFF];
    }
    return crc;
}

uint32_t napc_crc32c(const uint8_t *data, size_t len) {
    return crc32c_update(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

uint32_t napc_ocs_compute(const uint8_t *surplus, size_t surplus_len) {
    if (surplus_len < 4) return 0;
    uint32_t crc = crc32c_update(0xFFFFFFFFu, (const uint8_t*)"\0\0\0\0", 4);
    crc = crc32c_update(crc, surplus + 4, surplus_len - 4);
    return crc ^ 0xFFFFFFFFu;
}

void napc_write_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

uint32_t napc_generate_ident(void) {
    static uint32_t counter = 0;
    uint32_t id = 0;
    int got = 0;

#if defined(__linux__)
    ssize_t n = getrandom(&id, sizeof(id), 0);
    got = (n == (ssize_t)sizeof(id));
#endif
    if (!got) {
        static int urandom_fd = -2;
        if (urandom_fd == -2) urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (urandom_fd >= 0) {
            ssize_t n2 = read(urandom_fd, &id, sizeof(id));
            got = (n2 == (ssize_t)sizeof(id));
        }
    }
    if (!got) id = (uint32_t)time(NULL);

    id = id ^ (uint32_t)(++counter) ^ (uint32_t)(getpid() << 16);
    return id ? id : 1;
}

uint64_t napc_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
