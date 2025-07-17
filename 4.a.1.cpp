//  SM3 baseline reference implementation (Stage‑0)

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>


static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t P0(uint32_t x) { return x ^ rotl32(x, 9) ^ rotl32(x, 17); }
static inline uint32_t P1(uint32_t x) { return x ^ rotl32(x,15) ^ rotl32(x,23); }

static inline uint32_t FF(uint32_t a, uint32_t b, uint32_t c, int j) {
    return (j < 16) ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
}
static inline uint32_t GG(uint32_t e, uint32_t f, uint32_t g, int j) {
    return (j < 16) ? (e ^ f ^ g) : ((e & f) | (~e & g));
}
static inline uint32_t T(int j) {
    return (j < 16) ? 0x79CC4519u : 0x7A879D8Au;
}

struct SM3_CTX {
    uint32_t state[8];   // A,B,C,D,E,F,G,H
    uint64_t bitlen;     // total length processed (bits)
    uint8_t  buffer[64]; // partial block buffer
};

static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};


static void sm3_compress(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], Wp[64];

    // 1. message extension 
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t)block[i*4+0] << 24 | (uint32_t)block[i*4+1] << 16 |
                (uint32_t)block[i*4+2] <<  8 | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 68; ++i) {
        uint32_t tmp = W[i-16] ^ W[i-9] ^ rotl32(W[i-3], 15);
        W[i] = P1(tmp) ^ rotl32(W[i-13], 7) ^ W[i-6];
    }
    for (int i = 0; i < 64; ++i) Wp[i] = W[i] ^ W[i+4];

    // 2. iteration 
    uint32_t A=V[0], B=V[1], C=V[2], D=V[3];
    uint32_t E=V[4], F=V[5], G=V[6], H=V[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = rotl32((rotl32(A,12) + E + rotl32(T(j), j)) & 0xFFFFFFFFu, 7);
        uint32_t SS2 = SS1 ^ rotl32(A,12);
        uint32_t TT1 = (FF(A,B,C,j) + D + SS2 + Wp[j]) & 0xFFFFFFFFu;
        uint32_t TT2 = (GG(E,F,G,j) + H + SS1 + W[j])  & 0xFFFFFFFFu;
        D = C;
        C = rotl32(B,9);
        B = A;
        A = TT1;
        H = G;
        G = rotl32(F,19);
        F = E;
        E = P0(TT2);
    }

    // 3. feed‑forward 
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}


static void sm3_init(SM3_CTX *ctx) {
    std::memcpy(ctx->state, IV, sizeof(IV));
    ctx->bitlen = 0;
}

static void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = ctx->bitlen / 8 % 64;
    ctx->bitlen += len * 8ULL;

    size_t part = 64 - idx;
    size_t i = 0;

    if (idx && len >= part) {
        std::memcpy(ctx->buffer + idx, data, part);
        sm3_compress(ctx->state, ctx->buffer);
        i += part;
        idx = 0;
    }
    for (; i + 64 <= len; i += 64) {
        sm3_compress(ctx->state, data + i);
    }
    if (i < len) {
        std::memcpy(ctx->buffer + idx, data + i, len - i);
    }
}

static void sm3_final(SM3_CTX *ctx, uint8_t out[32]) {
    uint8_t pad[64] = {0x80};
    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i)
        len_be[i] = (ctx->bitlen >> (56 - 8*i)) & 0xFF;

    size_t idx = ctx->bitlen / 8 % 64;
    size_t padlen = (idx < 56) ? (56 - idx) : (120 - idx);

    sm3_update(ctx, pad, padlen);
    sm3_update(ctx, len_be, 8);

    for (int i = 0; i < 8; ++i) {
        out[i*4+0] = (ctx->state[i] >> 24) & 0xFF;
        out[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        out[i*4+2] = (ctx->state[i] >> 8 ) & 0xFF;
        out[i*4+3] = (ctx->state[i]      ) & 0xFF;
    }
}


#ifdef SM3_TEST_MAIN
int main(int argc, char *argv[]) {
    const char *msg = (argc > 1) ? argv[1] : "abc";
    SM3_CTX ctx;  uint8_t dig[32];
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t*)msg, std::strlen(msg));
    sm3_final(&ctx, dig);

    for (uint8_t b: dig) std::printf("%02X", b);
    std::printf("  %s\n", msg);
    return 0;
}
#endif
