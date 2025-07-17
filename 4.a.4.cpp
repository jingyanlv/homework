
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#ifdef USE_AVX2
    #include <immintrin.h>
#endif

#if defined(__GNUC__)
    #define RESTRICT __restrict__
#else
    #define RESTRICT
#endif

static inline uint32_t rotl32(uint32_t x, int n){ return (x<<n)|(x>>(32-n)); }
static inline uint32_t P0(uint32_t x){ return x ^ rotl32(x,9) ^ rotl32(x,17); }
static inline uint32_t P1(uint32_t x){ return x ^ rotl32(x,15)^ rotl32(x,23); }

#define FF00(a,b,c) ((a) ^ (b) ^ (c))
#define GG00(e,f,g) ((e) ^ (f) ^ (g))
#define FF16(a,b,c) (((a)&(b)) | ((a)&(c)) | ((b)&(c)))
#define GG16(e,f,g) (((e)&(f)) | (~(e)&(g)))

static const uint32_t TJROT32[64]={
    0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB,0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC,
    0xC4519799,0x88A32F33,0x11465E67,0x228CBCCE,0x4519799C,0x8A32F339,0x1465E673,0x28CBCCE6,
    0xDE6E56C6,0xBCDCAD8D,0x79B95B1B,0xF372B637,0xE6E56C6E,0xCDCAD8DD,0x9B95B1BB,0x372B6377,
    0x6E56C6EE,0xCDCACDD ,0xB95B1BB9,0x72B63773,0xE56C6EE6,0xCAD8DCCD,0x95B1BB9B,0x2B637737,
    0x56C6EE6E,0xAD8DCCD ,0x5B1BB9B9,0xB6377373,0x6C6EE6E6,0xD8DCCDCD,0xB1BB9B9B,0x63773737,
    0xC6EE6E6E,0x8DCCDCDC,0x1BB9B9B9,0x37737373,0x6EE6E6E6,0xDCCDCDCC,0xBB9B9B99,0x77373733,
    0xEE6E6E66,0x0DCDCDCC,0xB9B9B998,0x73737331,0xE6E6E662,0x0CDCDCC ,0x09B9B99 ,0x0373731 ,
    0x06E6E62 ,0x00DCDC  ,0x0B9B98  ,0x073731  ,0x0E6E62 ,0x00CDCC ,0x009B98 ,0x0031   };

// =============================================================================
//  Context Structure
// =============================================================================
struct SM3_CTX{
    uint32_t state[8];            // hash state
    uint64_t bitlen;             // total length in bits
    alignas(32) uint8_t buffer[64]; // partial block buffer (32-byte aligned for AVX2 loads)
};
static const uint32_t IV[8]={0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E};

// =============================================================================
//  ── Scalar Compression (Stage-2 single-pass W/W′) ──
// =============================================================================
static void sm3_compress_scalar(uint32_t V[8], const uint8_t block[64]){
    uint32_t W[68]; uint32_t Wp[64];
    for(int i=0;i<16;++i){
        W[i] = (uint32_t)block[i*4]<<24 | (uint32_t)block[i*4+1]<<16 |
                (uint32_t)block[i*4+2]<<8  | (uint32_t)block[i*4+3];
        if(i>=4) Wp[i-4] = W[i-4] ^ W[i];
    }
    for(int i=16;i<68;++i){
        uint32_t tmp = W[i-16]^W[i-9]^rotl32(W[i-3],15);
        W[i] = P1(tmp)^rotl32(W[i-13],7)^W[i-6];
        Wp[i-4] = W[i-4]^W[i];
    }
    uint32_t A=V[0],B=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7];
#define ROUND00(i) {\
    uint32_t SS1=rotl32((rotl32(A,12)+E+TJROT32[i])&0xFFFFFFFFu,7);\
    uint32_t SS2=SS1^rotl32(A,12);\
    uint32_t TT1=(FF00(A,B,C)+D+SS2+Wp[i])&0xFFFFFFFFu;\
    uint32_t TT2=(GG00(E,F,G)+H+SS1+W[i]) &0xFFFFFFFFu;\
    D=C; C=rotl32(B,9); B=A; A=TT1; H=G; G=rotl32(F,19); F=E; E=P0(TT2);} 
#define ROUND16(i) {\
    uint32_t SS1=rotl32((rotl32(A,12)+E+TJROT32[i])&0xFFFFFFFFu,7);\
    uint32_t SS2=SS1^rotl32(A,12);\
    uint32_t TT1=(FF16(A,B,C)+D+SS2+Wp[i])&0xFFFFFFFFu;\
    uint32_t TT2=(GG16(E,F,G)+H+SS1+W[i]) &0xFFFFFFFFu;\
    D=C; C=rotl32(B,9); B=A; A=TT1; H=G; G=rotl32(F,19); F=E; E=P0(TT2);} 
    ROUND00(0);  ROUND00(1);  ROUND00(2);  ROUND00(3);
    ROUND00(4);  ROUND00(5);  ROUND00(6);  ROUND00(7);
    ROUND00(8);  ROUND00(9);  ROUND00(10); ROUND00(11);
    ROUND00(12); ROUND00(13); ROUND00(14); ROUND00(15);
    for(int j=16;j<64;++j){
        if(j<32){ ROUND16(j); }
        else { ROUND16(j); }
    }
#undef ROUND00
#undef ROUND16
    V[0]^=A; V[1]^=B; V[2]^=C; V[3]^=D; V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
}

// =============================================================================
//  ── AVX2 Eight-way Parallel Compression ──
// =============================================================================
#ifdef USE_AVX2
//  Helpers for 32-bit rotate left on __m256i
static inline __m256i rotl32_vec(__m256i x, int n){
    return _mm256_or_si256(_mm256_slli_epi32(x,n), _mm256_srli_epi32(x,32-n));
}
//  Load 8×32-bit big-endian words into lanes [0..7]
static inline __m256i load_be256(const uint8_t *p){
    __m256i t = _mm256_loadu_si256((const __m256i*)p); // little-endian bytes
    // reverse bytes in each dword
    const __m256i shuffle = _mm256_setr_epi8( 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
                                             19,18,17,16,23,22,21,20,27,26,25,24,31,30,29,28);
    return _mm256_shuffle_epi8(t, shuffle);
}

static void sm3_compress_avx2(uint32_t V[8*8] RESTRICT, const uint8_t * RESTRICT blocks){
    // V: 8 parallel states concatenated (A0..H0, A1..H1, ... A7..H7)
    // blocks: 8×64-byte consecutive message blocks
    __m256i A,B,C,D,E,F,G,H;
    // Load states
    A=_mm256_loadu_si256((const __m256i*)(V+0));  // A0..A7
    B=_mm256_loadu_si256((const __m256i*)(V+8));
    C=_mm256_loadu_si256((const __m256i*)(V+16));
    D=_mm256_loadu_si256((const __m256i*)(V+24));
    E=_mm256_loadu_si256((const __m256i*)(V+32));
    F=_mm256_loadu_si256((const __m256i*)(V+40));
    G=_mm256_loadu_si256((const __m256i*)(V+48));
    H=_mm256_loadu_si256((const __m256i*)(V+56));

    __m256i W[68]; __m256i Wp;
    // 1) load first 16 words
    for(int i=0;i<16;++i){
        W[i]= load_be256(blocks + i*4*8); // interleaved blocks
    }
    // 2) expand W 16..67
    for(int i=16;i<68;++i){
        __m256i tmp = _mm256_xor_si256(_mm256_xor_si256(W[i-16], W[i-9]), rotl32_vec(W[i-3],15));
        W[i] = _mm256_xor_si256(_mm256_xor_si256(P1(tmp), rotl32_vec(W[i-13],7)), W[i-6]);
    }
    // Precompute W′ in-place later using XOR on the fly
    for(int j=0;j<64;++j){
        __m256i TJ = _mm256_set1_epi32(TJROT32[j]);
        __m256i SS1 = rotl32_vec(_mm256_add_epi32(_mm256_add_epi32(rotl32_vec(A,12),E),TJ),7);
        __m256i SS2 = _mm256_xor_si256(SS1, rotl32_vec(A,12));
        Wp = _mm256_xor_si256(W[j], W[j+4]);
        __m256i TT1, TT2;
        if(j<16){
            TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF00(A,B,C),D),SS2),Wp);
            TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG00(E,F,G),H),SS1),W[j]);
        }else{
            TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF16(A,B,C),D),SS2),Wp);
            TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG16(E,F,G),H),SS1),W[j]);
        }
        D=C; C=rotl32_vec(B,9); B=A; A=TT1;
        H=G; G=rotl32_vec(F,19); F=E; E=P0(TT2);
    }
    // Feed-forward
    A=_mm256_xor_si256(A, _mm256_loadu_si256((const __m256i*)(V+0)));
    B=_mm256_xor_si256(B, _mm256_loadu_si256((const __m256i*)(V+8)));
    C=_mm256_xor_si256(C, _mm256_loadu_si256((const __m256i*)(V+16)));
    D=_mm256_xor_si256(D, _mm256_loadu_si256((const __m256i*)(V+24)));
    E=_mm256_xor_si256(E, _mm256_loadu_si256((const __m256i*)(V+32)));
    F=_mm256_xor_si256(F, _mm256_loadu_si256((const __m256i*)(V+40)));
    G=_mm256_xor_si256(G, _mm256_loadu_si256((const __m256i*)(V+48)));
    H=_mm256_xor_si256(H, _mm256_loadu_si256((const __m256i*)(V+56)));

    // store back
    _mm256_storeu_si256((__m256i*)(V+0), A); _mm256_storeu_si256((__m256i*)(V+8), B);
    _mm256_storeu_si256((__m256i*)(V+16),C); _mm256_storeu_si256((__m256i*)(V+24),D);
    _mm256_storeu_si256((__m256i*)(V+32),E); _mm256_storeu_si256((__m256i*)(V+40),F);
    _mm256_storeu_si256((__m256i*)(V+48),G); _mm256_storeu_si256((__m256i*)(V+56),H);
}
#endif // USE_AVX2

// =============================================================================
//  Public API (unchanged)
// =============================================================================
static void sm3_init(SM3_CTX *ctx){ std::memcpy(ctx->state,IV,32); ctx->bitlen=0; }

static void sm3_update(SM3_CTX *ctx,const uint8_t * RESTRICT data,size_t len){
    size_t idx=(ctx->bitlen>>3)&0x3F; ctx->bitlen += (uint64_t)len<<3;
    size_t part=64-idx; size_t i=0;

    // Finish partial block first
    if(idx && len>=part){ std::memcpy(ctx->buffer+idx,data,part); sm3_compress_scalar(ctx->state,ctx->buffer); i+=part; idx=0; }

#ifdef USE_AVX2
    // Process 8-block batches using AVX2 when possible
    for(; i+512<=len; i+=512){
        // Copy current state into 8 parallel lanes (Ao..Ho etc.)
        alignas(32) uint32_t v8[64];
        for(int lane=0; lane<8; ++lane) std::memcpy(v8+lane*8, ctx->state, 32);
        sm3_compress_avx2(v8, data+i);
        // XOR-reduce lanes back into ctx->state
        for(int word=0; word<8; ++word){
            uint32_t acc=0; for(int lane=0; lane<8; ++lane) acc ^= v8[lane*8+word];
            ctx->state[word]=acc;
        }
    }
#endif
    // Scalar remainder blocks
    for(; i+64<=len; i+=64) sm3_compress_scalar(ctx->state,data+i);
    if(i<len) std::memcpy(ctx->buffer+idx,data+i,len-i);
}

static void sm3_final(SM3_CTX *ctx, uint8_t out[32]){
    uint8_t pad[64]={0x80}; uint8_t len_be[8];
    for(int i=0;i<8;++i) len_be[i]=(ctx->bitlen>>(56-8*i))&0xFF;
    size_t idx=(ctx->bitlen>>3)&0x3F; size_t padlen=(idx<56)?(56-idx):(120-idx);
    sm3_update(ctx,pad,padlen); sm3_update(ctx,len_be,8);
    for(int i