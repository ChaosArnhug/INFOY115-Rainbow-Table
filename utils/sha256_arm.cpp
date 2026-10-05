/*
* File: sha256_arm.cpp
 *
 * Author: voidxno
 * Created: 17 Feb 2024
 * Source: https://github.com/voidxno/fast-recursive-sha256
 *
 * Reference recursive SHA256 function, with intrinsics and ARM Cryptography Extensions
 *
 * Requirement: ARM CPU, with Cryptography Extensions
 *
 * LICENSE: Unlicense
 * For more information, please refer to <https://unlicense.org>
 *
 */

#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

// Include the appropriate headers for byte swapping
#if defined(_WIN32)
#include <intrin.h>
#define bswap_32(x) _byteswap_ulong(x)
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#elif defined(__GNUC__) || defined(__clang__)
#include <byteswap.h>
#else
static inline uint32_t bswap_32(uint32_t x) {
    return (x >> 24) |
           ((x >> 8) & 0x0000FF00) |
           ((x << 8) & 0x00FF0000) |
           (x << 24);
}
#endif

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

    // Initialize hash values
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

inline void compress_digest(uint32_t* state, const uint8_t* block)
{
    // Array of 64 constants for SHA-256 rounds
    static const uint32_t K64[64] = {
        0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,
        0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
        0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,
        0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
        0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,
        0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
        0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,
        0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
        0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,
        0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
        0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,
        0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
        0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,
        0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
        0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,
        0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
    };

    // Variables for SHA-256 rounds
    uint32x4_t STATE0;
    uint32x4_t STATE1;
    uint32x4_t STATE2;
    uint32x4_t MSG0;
    uint32x4_t MSG1;
    uint32x4_t MSG2;
    uint32x4_t MSG3;
    uint32x4_t TMP0;
    uint32x4_t TMP1;

    // Load state
    STATE0 = vld1q_u32(&state[0]); // A, B, C, D
    STATE1 = vld1q_u32(&state[4]); // E, F, G, H

    // Save initial state
    uint32x4_t ABEF_SAVE = STATE0;
    uint32x4_t CDGH_SAVE = STATE1;

    // Load message block and swap byte order
    MSG0 = vld1q_u32((const uint32_t*)(block));
    MSG1 = vld1q_u32((const uint32_t*)(block + 16));
    MSG2 = vld1q_u32((const uint32_t*)(block + 32));
    MSG3 = vld1q_u32((const uint32_t*)(block + 48));

    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

    // Rounds 0-15
    for (int i = 0; i < 16; i += 4) {
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K64[i]));
        STATE2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP0);

        TMP1 = vaddq_u32(MSG1, vld1q_u32(&K64[i + 1]));
        STATE2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP1);

        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K64[i + 2]));
        STATE2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP0);

        TMP1 = vaddq_u32(MSG3, vld1q_u32(&K64[i + 3]));
        STATE2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP1);

        // Message schedule updates
        if (i < 12) {
            MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);
            MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);
            MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);
            MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);
        }
    }

    // Rounds 16-63
    for (int i = 16; i < 64; i += 16) {
        // Update message schedule
        MSG0 = vsha256su1q_u32(MSG0, MSG1, MSG2);
        MSG1 = vsha256su1q_u32(MSG1, MSG2, MSG3);
        MSG2 = vsha256su1q_u32(MSG2, MSG3, MSG0);
        MSG3 = vsha256su1q_u32(MSG3, MSG0, MSG1);

        // Perform rounds
        for (int j = 0; j < 16; j += 4) {
            TMP0 = vaddq_u32(MSG0, vld1q_u32(&K64[i + j]));
            STATE2 = STATE0;
            STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
            STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP0);

            TMP1 = vaddq_u32(MSG1, vld1q_u32(&K64[i + j + 1]));
            STATE2 = STATE0;
            STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
            STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP1);

            TMP0 = vaddq_u32(MSG2, vld1q_u32(&K64[i + j + 2]));
            STATE2 = STATE0;
            STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
            STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP0);

            TMP1 = vaddq_u32(MSG3, vld1q_u32(&K64[i + j + 3]));
            STATE2 = STATE0;
            STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
            STATE1 = vsha256h2q_u32(STATE1, STATE2, TMP1);
        }
    }

    // Add the original state back
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    // Store the state back to the state array
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

// <eof>
