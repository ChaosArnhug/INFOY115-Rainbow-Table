/*
* File: sha256_x64.cpp
 *
 * Author: voidxno
 * Created: 12 Jun 2023
 * Source: https://github.com/voidxno/fast-recursive-sha256
 *
 * Reference recursive SHA256 function, with intrinsics and Intel SHA Extensions
 *
 * Requirement: Intel/AMD x64 CPU, with SHA Extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <stdint.h>
#include <string.h>

#if defined(__amd64__) || defined(_M_AMD64)
#include <immintrin.h>
#endif

#ifdef _WIN32
#include <intrin.h>
#endif

#ifdef _WIN32
#define bswap_32(x) _byteswap_ulong(x)
#else
#include <byteswap.h>
#endif

#if defined(__amd64__) || defined(_M_AMD64)

inline void compress_digest(uint32_t* state, const uint8_t* block);

void rsha256_ref(
    uint8_t*       hash,         // Output 32-byte hash
    const uint8_t* message,      // Input message
    size_t         message_len,  // Length of the input message
    const uint64_t num_iters)    // Number of iterations
{
    if (num_iters <= 0) return;

    // Allocate buffer for padded message
    size_t total_len = message_len + 1 + 8; // message + 0x80 + length
    size_t padded_len = ((total_len + 63) / 64) * 64;
    uint8_t* padded_message = new uint8_t[padded_len];
    memset(padded_message, 0x00, padded_len);

    // Copy the message
    memcpy(padded_message, message, message_len);

    // Append the '1' bit (0x80)
    padded_message[message_len] = 0x80;

    // Append the length in bits (big-endian)
    uint64_t bit_len = message_len * 8;
    for (int i = 0; i < 8; i++) {
        padded_message[padded_len - 1 - i] = (uint8_t)(bit_len >> (8 * i));
    }

    // Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    uint32_t state[8] = {
        0x6A09E667, 0xBB67AE85,
        0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C,
        0x1F83D9AB, 0x5BE0CD19
    };

    for (uint64_t iter = 0; iter < num_iters; ++iter) {
        // Process each 64-byte block
        for (size_t offset = 0; offset < padded_len; offset += 64) {
            compress_digest(state, padded_message + offset);
        }

        // Prepare for next iteration
        if (iter + 1 < num_iters) {
            // Copy the current hash to the message for the next iteration
            memcpy(padded_message, state, 32);
            // Reset the padding
            memset(padded_message + 32, 0x00, padded_len - 32);
            padded_message[32] = 0x80;
            bit_len = 32 * 8;
            for (int i = 0; i < 8; i++) {
                padded_message[padded_len - 1 - i] = (uint8_t)(bit_len >> (8 * i));
            }
            // Reset state
            state[0] = 0x6A09E667; state[1] = 0xBB67AE85;
            state[2] = 0x3C6EF372; state[3] = 0xA54FF53A;
            state[4] = 0x510E527F; state[5] = 0x9B05688C;
            state[6] = 0x1F83D9AB; state[7] = 0x5BE0CD19;
        }
    }

    // Convert state to big-endian and copy to hash
    for (int i = 0; i < 8; i++) {
        state[i] = bswap_32(state[i]);
    }
    memcpy(hash, state, 32);

    delete[] padded_message;
}

inline void compress_digest(uint32_t* state,const uint8_t* last)
{

 //-- array of 64x constants for SHA256 rounds
 alignas(64) static const uint32_t K64[64] = {
   0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
   0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
   0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
   0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
   0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
   0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
   0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
   0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
   };

 //-- shuffle mask for byte order required by SHA Extensions
 const __m128i SHUF_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B,0x0405060700010203);

 //-- variables to calculate SHA256 rounds
 __m128i STATE0;
 __m128i STATE1;
 __m128i MSGV;
 __m128i MSGTMP0;
 __m128i MSGTMP1;
 __m128i MSGTMP2;
 __m128i MSGTMP3;

 //-- init state value for SHA256 rounds
 STATE0 = _mm_loadu_si128((__m128i*)(&state[0]));
 STATE1 = _mm_loadu_si128((__m128i*)(&state[4]));

 //-- shuffle state bytes required by SHA Extensions
 STATE0 = _mm_shuffle_epi32(STATE0,0xB1); // CDAB
 STATE1 = _mm_shuffle_epi32(STATE1,0x1B); // EFGH
 MSGTMP0 = _mm_alignr_epi8(STATE0,STATE1,8);   // ABEF
 STATE1 = _mm_blend_epi16(STATE1,STATE0,0xF0); // CDGH
 STATE0 = MSGTMP0;

 //-- save current state for usage later
 const __m128i ABEF_SAVE = STATE0;
 const __m128i CDGH_SAVE = STATE1;

 //-- rounds 0-3
 MSGV = _mm_loadu_si128((__m128i*)(&last[0]));
 MSGV = _mm_shuffle_epi8(MSGV,SHUF_MASK);
 MSGTMP0 = MSGV;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[0])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);

 //-- rounds 4-7
 MSGV = _mm_loadu_si128((__m128i*)(&last[16]));
 MSGV = _mm_shuffle_epi8(MSGV,SHUF_MASK);
 MSGTMP1 = MSGV;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[4])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP0 = _mm_sha256msg1_epu32(MSGTMP0,MSGTMP1);

 //-- rounds 8-11
 MSGV = _mm_loadu_si128((__m128i*)(&last[32]));
 MSGV = _mm_shuffle_epi8(MSGV,SHUF_MASK);
 MSGTMP2 = MSGV;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[8])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP1 = _mm_sha256msg1_epu32(MSGTMP1,MSGTMP2);

 //-- rounds 12-15
 MSGV = _mm_loadu_si128((__m128i*)(&last[48]));
 MSGV = _mm_shuffle_epi8(MSGV,SHUF_MASK);
 MSGTMP3 = MSGV;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[12])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP0 = _mm_add_epi32(MSGTMP0,_mm_alignr_epi8(MSGTMP3,MSGTMP2,4));
 MSGTMP0 = _mm_sha256msg2_epu32(MSGTMP0,MSGTMP3);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP2 = _mm_sha256msg1_epu32(MSGTMP2,MSGTMP3);

 //-- rounds 16-19
 MSGV = MSGTMP0;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[16])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP1 = _mm_add_epi32(MSGTMP1,_mm_alignr_epi8(MSGTMP0,MSGTMP3,4));
 MSGTMP1 = _mm_sha256msg2_epu32(MSGTMP1,MSGTMP0);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP3 = _mm_sha256msg1_epu32(MSGTMP3,MSGTMP0);

 //-- rounds 20-23
 MSGV = MSGTMP1;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[20])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP2 = _mm_add_epi32(MSGTMP2,_mm_alignr_epi8(MSGTMP1,MSGTMP0,4));
 MSGTMP2 = _mm_sha256msg2_epu32(MSGTMP2,MSGTMP1);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP0 = _mm_sha256msg1_epu32(MSGTMP0,MSGTMP1);

 //-- rounds 24-27
 MSGV = MSGTMP2;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[24])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP3 = _mm_add_epi32(MSGTMP3,_mm_alignr_epi8(MSGTMP2,MSGTMP1,4));
 MSGTMP3 = _mm_sha256msg2_epu32(MSGTMP3,MSGTMP2);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP1 = _mm_sha256msg1_epu32(MSGTMP1,MSGTMP2);

 //-- rounds 28-31
 MSGV = MSGTMP3;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[28])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP0 = _mm_add_epi32(MSGTMP0,_mm_alignr_epi8(MSGTMP3,MSGTMP2,4));
 MSGTMP0 = _mm_sha256msg2_epu32(MSGTMP0,MSGTMP3);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP2 = _mm_sha256msg1_epu32(MSGTMP2,MSGTMP3);

 //-- rounds 32-35
 MSGV = MSGTMP0;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[32])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP1 = _mm_add_epi32(MSGTMP1,_mm_alignr_epi8(MSGTMP0,MSGTMP3,4));
 MSGTMP1 = _mm_sha256msg2_epu32(MSGTMP1,MSGTMP0);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP3 = _mm_sha256msg1_epu32(MSGTMP3,MSGTMP0);

 //-- rounds 36-39
 MSGV = MSGTMP1;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[36])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP2 = _mm_add_epi32(MSGTMP2,_mm_alignr_epi8(MSGTMP1,MSGTMP0,4));
 MSGTMP2 = _mm_sha256msg2_epu32(MSGTMP2,MSGTMP1);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP0 = _mm_sha256msg1_epu32(MSGTMP0,MSGTMP1);

 //-- rounds 40-43
 MSGV = MSGTMP2;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[40])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP3 = _mm_add_epi32(MSGTMP3,_mm_alignr_epi8(MSGTMP2,MSGTMP1,4));
 MSGTMP3 = _mm_sha256msg2_epu32(MSGTMP3,MSGTMP2);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP1 = _mm_sha256msg1_epu32(MSGTMP1,MSGTMP2);

 //-- rounds 44-47
 MSGV = MSGTMP3;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[44])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP0 = _mm_add_epi32(MSGTMP0,_mm_alignr_epi8(MSGTMP3,MSGTMP2,4));
 MSGTMP0 = _mm_sha256msg2_epu32(MSGTMP0,MSGTMP3);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP2 = _mm_sha256msg1_epu32(MSGTMP2,MSGTMP3);

 //-- rounds 48-51
 MSGV = MSGTMP0;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[48])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP1 = _mm_add_epi32(MSGTMP1,_mm_alignr_epi8(MSGTMP0,MSGTMP3,4));
 MSGTMP1 = _mm_sha256msg2_epu32(MSGTMP1,MSGTMP0);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);
 MSGTMP3 = _mm_sha256msg1_epu32(MSGTMP3,MSGTMP0);

 //-- rounds 52-55
 MSGV = MSGTMP1;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[52])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP2 = _mm_add_epi32(MSGTMP2,_mm_alignr_epi8(MSGTMP1,MSGTMP0,4));
 MSGTMP2 = _mm_sha256msg2_epu32(MSGTMP2,MSGTMP1);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);

 //-- rounds 56-59
 MSGV = MSGTMP2;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[56])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGTMP3 = _mm_add_epi32(MSGTMP3,_mm_alignr_epi8(MSGTMP2,MSGTMP1,4));
 MSGTMP3 = _mm_sha256msg2_epu32(MSGTMP3,MSGTMP2);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);

 //-- rounds 60-63
 MSGV = MSGTMP3;
 MSGV = _mm_add_epi32(MSGV,_mm_load_si128((__m128i*)(&K64[60])));
 STATE1 = _mm_sha256rnds2_epu32(STATE1,STATE0,MSGV);
 MSGV = _mm_shuffle_epi32(MSGV,0x0E);
 STATE0 = _mm_sha256rnds2_epu32(STATE0,STATE1,MSGV);

 //-- add init state to current state
 STATE0 = _mm_add_epi32(STATE0,ABEF_SAVE);
 STATE1 = _mm_add_epi32(STATE1,CDGH_SAVE);

 //-- shuffle SHA Extensions state value back, save for next iteration or final result
 STATE0 = _mm_shuffle_epi32(STATE0,0x1B); // FEBA
 STATE1 = _mm_shuffle_epi32(STATE1,0xB1); // DCHG
 _mm_storeu_si128((__m128i*)(&state[0]),_mm_blend_epi16(STATE0,STATE1,0xF0)); // DCBA
 _mm_storeu_si128((__m128i*)(&state[4]),_mm_alignr_epi8(STATE1,STATE0,8));    // HGFE
}

#endif

// <eof>