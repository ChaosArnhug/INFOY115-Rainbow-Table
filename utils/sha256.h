#ifndef RSHA256_REF_H
#define RSHA256_REF_H

#include <stdint.h>
#include <string.h>

// Include architecture-specific headers
#if defined(__amd64__) || defined(_M_AMD64)
    #include <immintrin.h>
#elif defined(__aarch64__) || defined(_M_ARM64)
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
    #define bswap_32(x) __builtin_bswap32(x)  // Corrected to use GCC/Clang built-in
#else
    static inline uint32_t bswap_32(uint32_t x) {
        return (x >> 24) |
               ((x >> 8) & 0x0000FF00) |
               ((x << 8) & 0x00FF0000) |
               (x << 24);
    }
#endif

// Declare rsha256_ref and related functions for supported architectures
#if defined(__amd64__) || defined(_M_AMD64) || defined(__aarch64__) || defined(_M_ARM64)

    /**
     * @brief Compresses a single 64-byte SHA-256 block.
     *
     * @param state Pointer to the current state (8 uint32_t values).
     * @param block Pointer to the 64-byte input block.
     */
    inline void compress_digest(uint32_t* state, const uint8_t* block);

    /**
     * @brief Reference implementation of recursive SHA-256 hashing.
     *
     * @param hash        Output buffer for the 32-byte hash.
     * @param message     Input message to hash.
     * @param message_len Length of the input message in bytes.
     * @param num_iters   Number of hashing iterations to perform.
     */
    void rsha256_ref(
        uint8_t*       hash,         // Output 32-byte hash
        const uint8_t* message,      // Input message
        size_t         message_len,  // Length of the input message
        const uint64_t num_iters);   // Number of iterations

    // If there was a duplicate declaration, ensure it's removed.
    // The following line was present in the original header and should be removed:
    // inline void compress_digest(uint32_t* state, const uint8_t* last);

#endif // Supported architectures

#endif // RSHA256_REF_H
