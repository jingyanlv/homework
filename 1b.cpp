#include <iostream>
#include <iomanip>
#include <cstring>
#include <immintrin.h>
#include <wmmintrin.h>
#include <array>
#include <vector>
#include <1a.cpp>
class SM4_TTable {
private:
    static const uint8_t S_BOX[256];
    static const uint32_t FK[4];
    static const uint32_t CK[32];

    uint32_t rk[ROUNDS];
    uint32_t T[4][256]; // T-table

    void init_T_table() {
        for (int i = 0; i < 256; i++) {
            uint32_t a = S_BOX[i];
            uint32_t b = (a << 24) | (a << 16) | (a << 8) | a;
            T[0][i] = b ^ rotate_left(b, 2) ^ rotate_left(b, 10) ^ rotate_left(b, 18) ^ rotate_left(b, 24);
            T[1][i] = rotate_left(T[0][i], 24);
            T[2][i] = rotate_left(T[0][i], 16);
            T[3][i] = rotate_left(T[0][i], 8);
        }
    }

    uint32_t rotate_left(uint32_t x, uint8_t n) {
        return (x << n) | (x >> (32 - n));
    }

public:
    SM4_TTable() {
        init_T_table();
    }

    void set_key(const uint8_t key[16]) {
        uint32_t K[4];
        for (int i = 0; i < 4; ++i) {
            K[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) |
                (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        for (int i = 0; i < 4; ++i) {
            K[i] ^= FK[i];
        }

        for (int i = 0; i < ROUNDS; ++i) {
            uint32_t T_val = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];

         
            uint32_t B = (T_val >> 24) & 0xFF;
            uint32_t result = T[0][B];
            B = (T_val >> 16) & 0xFF;
            result ^= T[1][B];
            B = (T_val >> 8) & 0xFF;
            result ^= T[2][B];
            B = T_val & 0xFF;
            result ^= T[3][B];

            rk[i] = K[i % 4] ^ (result ^ rotate_left(result, 13) ^ rotate_left(result, 23));
            K[i % 4] = rk[i];
        }
    }

    void encrypt(const uint8_t in[16], uint8_t out[16]) {
        uint32_t X[36];
        for (int i = 0; i < 4; ++i) {
            X[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) |
                (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < ROUNDS; ++i) {
            uint32_t T_val = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];

     
            uint32_t B = (T_val >> 24) & 0xFF;
            uint32_t result = T[0][B];
            B = (T_val >> 16) & 0xFF;
            result ^= T[1][B];
            B = (T_val >> 8) & 0xFF;
            result ^= T[2][B];
            B = T_val & 0xFF;
            result ^= T[3][B];

            X[i + 4] = X[i] ^ result;
        }

        for (int i = 0; i < 4; ++i) {
            out[i * 4] = (X[35 - i] >> 24) & 0xFF;
            out[i * 4 + 1] = (X[35 - i] >> 16) & 0xFF;
            out[i * 4 + 2] = (X[35 - i] >> 8) & 0xFF;
            out[i * 4 + 3] = X[35 - i] & 0xFF;
        }
    }

    void decrypt(const uint8_t in[16], uint8_t out[16]) {
        uint32_t X[36];
        for (int i = 0; i < 4; ++i) {
            X[i] = (in[i * 4] << 24) | (in[i * 4 + 1] << 16) |
                (in[i * 4 + 2] << 8) | in[i * 4 + 3];
        }

        for (int i = 0; i < ROUNDS; ++i) {
            uint32_t T_val = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[ROUNDS - 1 - i];

            
            uint32_t B = (T_val >> 24) & 0xFF;
            uint32_t result = T[0][B];
            B = (T_val >> 16) & 0xFF;
            result ^= T[1][B];
            B = (T_val >> 8) & 0xFF;
            result ^= T[2][B];
            B = T_val & 0xFF;
            result ^= T[3][B];

            X[i + 4] = X[i] ^ result;
        }

        for (int i = 0; i < 4; ++i) {
            out[i * 4] = (X[35 - i] >> 24) & 0xFF;
            out[i * 4 + 1] = (X[35 - i] >> 16) & 0xFF;
            out[i * 4 + 2] = (X[35 - i] >> 8) & 0xFF;
            out[i * 4 + 3] = X[35 - i] & 0xFF;
        }
    }
};


#ifdef __AES__
class SM4_AESNI {
private:
    __m128i rk[32];
    static const uint8_t S_BOX[256];
    static const uint32_t FK[4];
    static const uint32_t CK[32];

    __m128i sm4_sbox_aesni(__m128i x) {
   
        x = _mm_aesenc_si128(x, _mm_setzero_si128());
        x = _mm_aesenclast_si128(x, _mm_setzero_si128());
        return x;
    }

    __m128i sm4_round(__m128i x0, __m128i x1, __m128i x2, __m128i x3, __m128i rk) {
        __m128i T_val = _mm_xor_si128(_mm_xor_si128(x1, x2), _mm_xor_si128(x3, rk));
        T_val = sm4_sbox_aesni(T_val);
        return _mm_xor_si128(x0, T_val);
    }

public:
    void set_key(const uint8_t key[16]) {
        __m128i K[4];
        K[0] = _mm_loadu_si128((const __m128i*)key);

        for (int i = 0; i < ROUNDS; i++) {
           
            rk[i] = _mm_aeskeygenassist_si128(K[0], i);
        }
    }

    void encrypt(const uint8_t in[16], uint8_t out[16]) {
        __m128i state = _mm_loadu_si128((const __m128i*)in);

        for (int i = 0; i < ROUNDS; i++) {
          
        }

        _mm_storeu_si128((__m128i*)out, state);
    }

    void decrypt(const uint8_t in[16], uint8_t out[16]) {
        __m128i state = _mm_loadu_si128((const __m128i*)in);

        for (int i = ROUNDS - 1; i >= 0; i--) {
       
        }

        _mm_storeu_si128((__m128i*)out, state);
    }
};
#endif


#if defined(__GFNI__) && defined(__AVX512F__)
class SM4_GFNI_AVX512 {
private:
    __m512i rk[32];

    __m512i sm4_sbox_gfni(__m512i x) {
        const __m512i affine_matrix = _mm512_set1_epi64(0xC6A1B5D7E390F284); 
        const __m512i constant_term = _mm512_set1_epi8(0x63);

        x = _mm512_gf2p8affine_epi64_epi8(x, affine_matrix, 0);
        x = _mm512_xor_si512(x, constant_term);
        return x;
    }

    
    __m512i sm4_linear(__m512i x) {
        __m512i t0 = _mm512_rol_epi32(x, 2);
        __m512i t1 = _mm512_rol_epi32(x, 10);
        __m512i t2 = _mm512_rol_epi32(x, 18);
        __m512i t3 = _mm512_rol_epi32(x, 24);
        return _mm512_xor_epi32(_mm512_xor_epi32(x, t0),
            _mm512_xor_epi32(t1, _mm512_xor_epi32(t2, t3)));
    }

    __m512i sm4_round(__m512i x0, __m512i x1, __m512i x2, __m512i x3, __m512i rk) {
        __m512i T_val = _mm512_xor_epi32(_mm512_xor_epi32(x1, x2),
            _mm512_xor_epi32(x3, rk));
        T_val = sm4_sbox_gfni(T_val);
        T_val = sm4_linear(T_val);
        return _mm512_xor_epi32(x0, T_val);
    }

public:
    void set_key(const uint8_t key[16]) {
       
        __m128i key128 = _mm_loadu_si128((const __m128i*)key);
        __m512i key512 = _mm512_broadcast_i32x4(key128);

        for (int i = 0; i < ROUNDS; i++) {
            
            rk[i] = key512; 
        }
    }

   
    void encrypt_4blocks(const uint8_t in[64], uint8_t out[64]) {
        __m512i block0 = _mm512_loadu_si512((const __m512i*)(in));
        __m512i block1 = _mm512_loadu_si512((const __m512i*)(in + 16));
        __m512i block2 = _mm512_loadu_si512((const __m512i*)(in + 32));
        __m512i block3 = _mm512_loadu_si512((const __m512i*)(in + 48));

        

        _mm512_storeu_si512((__m512i*)out, block0);
        _mm512_storeu_si512((__m512i*)(out + 16), block1);
        _mm512_storeu_si512((__m512i*)(out + 32), block2);
        _mm512_storeu_si512((__m512i*)(out + 48), block3);
    }

    void encrypt(const uint8_t in[16], uint8_t out[16]) {
        uint8_t tmp_in[64] = { 0 };
        uint8_t tmp_out[64] = { 0 };
        memcpy(tmp_in, in, 16);
        encrypt_4blocks(tmp_in, tmp_out);
        memcpy(out, tmp_out, 16);
    }
};
#endif


void benchmark_sm4() {
    
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint8_t plain[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint8_t cipher[16];

    
    SM4_Basic sm4_basic;
    sm4_basic.set_key(key);

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++) {
        sm4_basic.encrypt(plain, cipher);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Basic SM4: "
        << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
        << " ms" << std::endl;

 
    SM4_TTable sm4_ttable;
    sm4_ttable.set_key(key);

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++) {
        sm4_ttable.encrypt(plain, cipher);
    }
    end = std::chrono::high_resolution_clock::now();
    std::cout << "T-table SM4: "
        << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
        << " ms" << std::endl;

   
#ifdef __AES__
    SM4_AESNI sm4_aesni;
    sm4_aesni.set_key(key);

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++) {
        sm4_aesni.encrypt(plain, cipher);
    }
    end = std::chrono::high_resolution_clock::now();
    std::cout << "AES-NI SM4: "
        << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
        << " ms" << std::endl;
#endif

    
#if defined(__GFNI__) && defined(__AVX512F__)
    SM4_GFNI_AVX512 sm4_gfni;
    sm4_gfni.set_key(key);

    
    uint8_t plain4[64];
    uint8_t cipher4[64];
    for (int i = 0; i < 4; i++) {
        memcpy(plain4 + i * 16, plain, 16);
    }

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 250000; i++) { // 1000000/4=250000
        sm4_gfni.encrypt_4blocks(plain4, cipher4);
    }
    end = std::chrono::high_resolution_clock::now();
    std::cout << "GFNI+AVX512 SM4 (4 blocks): "
        << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
        << " ms" << std::endl;
#endif
}

int main() {
    benchmark_sm4();
    return 0;
}


const uint8_t SM4_TTable::S_BOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

const uint32_t SM4_TTable::FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

const uint32_t SM4_TTable::CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};