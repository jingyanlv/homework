//  SM3 Stage‑1 Optimised Implementation: Loop Unrolling + Macros

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t P0(uint32_t x) { return x ^ rotl32(x, 9) ^ rotl32(x,17); }
static inline uint32_t P1(uint32_t x) { return x ^ rotl32(x,15) ^ rotl32(x,23); }

#define FF00(a,b,c) ((a) ^ (b) ^ (c))
#define GG00(e,f,g) ((e) ^ (f) ^ (g))
#define FF16(a,b,c) (((a) & (b)) | ((a) & (c)) | ((b) & (c)))
#define GG16(e,f,g) (((e) & (f)) | (~(e) & (g)))

// Pre‑rotated constants for j=0…63  (rotl(Tj, j))
static const uint32_t TJROT[64] = {
    /* 0‑15: Tj=0x79CC4519 */
    0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB,0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC,
    0xC4519799,0x88A32F33,0x11465E67,0x228CBCCE,0x4519799C,0x8A32F339,0x1465E673,0x28CBCCE6,
    /* 16‑63: Tj=0x7A879D8A */
    0xDE6E56C6,0xBCDCAD8D,0x79B95B1B,0xF372B637,0xE6E56C6E,0xCDCAD8DD,0x9B95B1BB,0x372B6377,
    0x6E56C6EE,0xCDCACDD,0xB95B1BB9,0x72B63773,0xE56C6EE6,0xCAD8DCCD,0x95B1BB9B,0x2B637737,
    0x56C6EE6E,0xAD8DCCD,0x5B1BB9B9,0xB6377373,0x6C6EE6E6,0xD8DCCDCD,0xB1BB9B9B,0x63773737,
    0xC6EE6E6E,0x8DCCDCDC,0x1BB9B9B9,0x37737373,0x6EE6E6E6,0xDCCDCDCC,0xBB9B9B99,0x77373733,
    0xEE6E6E66,0xDCDCDC,0xB9B9B998,0x73737331,0xE6E6E662,0xCDCDCC,0x9B9B99,0x373731,
    0x6E6E62,0xDCDC,0xB9B98,0x73731,0xE6E62,0xCDCC,0x9B98,0x3731,
    0x6E62,0xDCC,0xB98,0x731,0xE62,0xCC,0x98,0x31
};


#define ROUND00(i) do { \
    uint32_t SS1 = rotl32((rotl32(A,12) + E + TJROT[i]) & 0xFFFFFFFFu, 7); \
    uint32_t SS2 = SS1 ^ rotl32(A,12); \
    uint32_t TT1 = (FF00(A,B,C) + D + SS2 + Wp[i]) & 0xFFFFFFFFu; \
    uint32_t TT2 = (GG00(E,F,G) + H + SS1 + W[i])  & 0xFFFFFFFFu; \
    D=C; C=rotl32(B,9); B=A; A=TT1; \
    H=G; G=rotl32(F,19); F=E; E=P0(TT2); \
} while(0)

#define ROUND16(i) do { \
    uint32_t SS1 = rotl32((rotl32(A,12) + E + TJROT[i]) & 0xFFFFFFFFu, 7); \
    uint32_t SS2 = SS1 ^ rotl32(A,12); \
    uint32_t TT1 = (FF16(A,B,C) + D + SS2 + Wp[i]) & 0xFFFFFFFFu; \
    uint32_t TT2 = (GG16(E,F,G) + H + SS1 + W[i])  & 0xFFFFFFFFu; \
    D=C; C=rotl32(B,9); B=A; A=TT1; \
    H=G; G=rotl32(F,19); F=E; E=P0(TT2); \
} while(0)


struct SM3_CTX {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
};
static const uint32_t IV[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};


static void sm3_compress(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], Wp[64];


    for (int i=0;i<16;++i) {
        W[i] = (uint32_t)block[i*4]   << 24 | (uint32_t)block[i*4+1] << 16 |
                (uint32_t)block[i*4+2] << 8 | (uint32_t)block[i*4+3];
    }
    for (int i=16;i<68;++i) {
        uint32_t tmp = W[i-16] ^ W[i-9] ^ rotl32(W[i-3],15);
        W[i] = P1(tmp) ^ rotl32(W[i-13],7) ^ W[i-6];
    }
    for (int i=0;i<64;++i) Wp[i] = W[i] ^ W[i+4];


    uint32_t A=V[0], B=V[1], C=V[2], D=V[3];
    uint32_t E=V[4], F=V[5], G=V[6], H=V[7];


    ROUND00(0);  ROUND00(1);  ROUND00(2);  ROUND00(3);
    ROUND00(4);  ROUND00(5);  ROUND00(6);  ROUND00(7);
    ROUND00(8);  ROUND00(9);  ROUND00(10); ROUND00(11);
    ROUND00(12); ROUND00(13); ROUND00(14); ROUND00(15);

    ROUND16(16); ROUND16(17); ROUND16(18); ROUND16(19);
    ROUND16(20); ROUND16(21); ROUND16(22); ROUND16(23);
    ROUND16(24); ROUND16(25); ROUND16(26); ROUND16(27);
    ROUND16(28); ROUND16(29); ROUND16(30); ROUND16(31);
    ROUND16(32); ROUND16(33); ROUND16(34); ROUND16(35);
    ROUND16(36); ROUND16(37); ROUND16(38); ROUND16(39);
    ROUND16(40); ROUND16(41); ROUND16(42); ROUND16(43);
    ROUND16(44); ROUND16(45); ROUND16(46); ROUND16(47);
    ROUND16(48); ROUND16(49); ROUND16(50); ROUND16(51);
    ROUND16(52); ROUND16(53); ROUND16(54); ROUND16(55);
    ROUND16(56); ROUND16(57); ROUND16(58); ROUND16(59);
    ROUND16(60); ROUND16(61); ROUND16(62); ROUND16(63);

    V[0]^=A; V[1]^=B; V[2]^=C; V[3]^=D;
    V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
}


static void sm3_init(SM3_CTX *ctx) {
    std::memcpy(ctx->state, IV, sizeof(IV));
    ctx->bitlen = 0;
}
static void sm3_update(SM3_CTX *ctx,const uint8_t *data,size_t len){
    size_t idx = (ctx->bitlen/8)%64; ctx->bitlen += (uint64_t)len*8;
    size_t part=64-idx, i=0;
    if(idx && len>=part){ std::memcpy(ctx->buffer+idx,data,part); sm3_compress(ctx->state,ctx->buffer); i+=part; idx=0; }
    for(; i+64<=len; i+=64) sm3_compress(ctx->state,data+i);
    if(i<len) std::memcpy(ctx->buffer+idx,data+i,len-i);
}
static void sm3_final(SM3_CTX *ctx, uint8_t out[32]){
    uint8_t pad[64]={0x80}; uint8_t len_be[8];
    for(int i=0;i<8;++i) len_be[i]=(ctx->bitlen>>(56-8*i))&0xFF;
    size_t idx=(ctx->bitlen/8)%64; size_t padlen=(idx<56)?(56-idx):(120-idx);
    sm3_update(ctx,pad,padlen); sm3_update(ctx,len_be,8);
    for(int i=0;i<8;++i){ out[i*4+0]=(ctx->state[i]>>24)&0xFF; out[i*4+1]=(ctx->state[i]>>16)&0xFF; out[i*4+2]=(ctx->state[i]>>8)&0xFF; out[i*4+3]=ctx->state[i]&0xFF; }
}

#ifdef SM3_TEST_MAIN
int main(int argc,char *argv[]){ const char *msg=(argc>1)?argv[1]:"abc"; SM3_CTX ctx; uint8_t dig[32];
    sm3_init(&ctx); sm3_update(&ctx,(const uint8_t*)msg,std::strlen(msg)); sm3_final(&ctx,dig);
    for(uint8_t b:dig) std::printf("%02X",b); std::printf("  %s\n",msg); return 0; }
#endif
