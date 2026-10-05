/*
* File: rainbow.cpp
*
* Authors: Gardeur Nicolas, Hennen Cyril, Ishimwe Daniel, Meunier Arnaud
* Created: 13th of October 2024
* Source: https://gitlab.com/info-y115/rainbow-table
*
* Description:
* This file implements the generation of a rainbow table using multithreading for
* cracking SHA-256 hashes. It supports both portable SHA-256 and optimized versions 
* utilizing x64 intrinsics or ARM Cryptography Extensions, depending on the architecture. 
* The reduction function and password generation process are crucial to the table's structure.
*
*/

#include "./utils/welcome.hpp"
#include "constants.hpp"
#include "./utils/threadpool.hpp"
#include <iostream>
#include <fstream>
#include <random>
#include <iomanip>
#include <string>
#include <cstdlib>
#include <chrono>
#include <atomic>
#include <thread>
#include <cstdint>
#include <vector>
#include <array>
#include <filesystem>
#include <cstring>

#if defined(USE_PORTABLE_SHA256)
#include "./utils/sha256_portable.h"
#else
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif
#include "./utils/sha256.h"
#endif

// Define HashType & PswCodeFormat
using HashType = std::array<uint8_t, 32>;
using PswCodeFormat = std::array<uint8_t, 10>;

// Initialize random number generator once
std::random_device rd;
std::mt19937 rng(rd());
std::uniform_int_distribution<> dist_char(0, static_cast<int>(CHARSET.size()) - 1);

// Atomic counter for progress tracking
std::atomic<int64_t> total_completed(0);

// Function to compute SHA-256 hash and return HashType
static HashType sha256_raw(const void *data, const size_t numBytes) {
    HashType hashBytes;
#if defined(USE_PORTABLE_SHA256)
    // Use the portable SHA256 implementation
    SHA256 sha;
    sha.add(data, numBytes);
    sha.getHash(hashBytes.data());
#else
    rsha256_ref(hashBytes.data(), (const uint8_t *) data, numBytes, 1);
#endif
    return hashBytes;
}

// Function to convert HashType to hex string
std::string bytesToHexString(const HashType &bytes) {
    std::stringstream ss;
    for (const unsigned char c: bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

// Reduction function
static std::string reduce(const HashType &hashBytes, int reductionIndex, size_t passwordLength) {
    std::string password;
    password.reserve(passwordLength);
    const size_t hashLength = hashBytes.size();

    for (int i = 0; i < passwordLength; ++i) {
        password += CHARSET[hashBytes[(reductionIndex + i * 7) % hashLength] % CHARSET.size()];
    }

    return password;
}

/*
std::string  map_reduction_number_to_chars(const PswCodeFormat& code, size_t passwordLength) {
    std::string password;
    for (size_t i = 0; i < passwordLength; ++i) {
        password += CHARSET[code[i]]; // Assurez-vous que CHARSET est bien déclaré globalement
    }
    return password;
}
*/

// Function to generate random passwords of a fixed length
static std::string generatePassword(size_t passwordLength) {
    std::string password;
    password.reserve(passwordLength);
    for (int i = 0; i < passwordLength; ++i) {
        password += CHARSET[dist_char(rng)];
    }

    return password;
}


// Generate a portion of the rainbow table
void generateRainbowTableChunk(const int start, const int end, const std::string &filename, size_t passwordLength,
                               int chainLength) {
    std::ofstream rainbowTable(filename, std::ios::out | std::ios::app);
    if (!rainbowTable.is_open()) {
        std::cerr << "[ERROR] Error opening file for rainbow table.\n";
        exit(EXIT_FAILURE);
    }

    for (int i = start; i < end; ++i) {
        std::string startPassword = generatePassword(passwordLength);
        std::string currentPassword = startPassword;

        for (int j = 0; j < chainLength; ++j) {
            HashType hashBytes = sha256_raw((currentPassword.c_str()), passwordLength);
            currentPassword = reduce(hashBytes, j, passwordLength);
        }

        // Store the start password and the tail (final reduced password)
        rainbowTable << startPassword << " " << currentPassword << "\n";
        total_completed++; // Increment the total completed count
    }
    rainbowTable.close();
}

// Generate a rainbow table using multithreading
void generateRainbowTable(int tableSize, const std::string &baseFilename, size_t passwordLength, int chainLength) {
    int num_threads = static_cast<int>(std::thread::hardware_concurrency());
    if (num_threads == 0) num_threads = 4; // Default to 4 threads if unable to detect

    ThreadPool pool(num_threads);

    const int chunk_size = tableSize / num_threads;
    const int remainder = tableSize % num_threads;

    std::vector<std::future<void> > futures;

    int start = 0;
    for (int t = 0; t < num_threads; ++t) {
        int end = start + chunk_size + (t < remainder ? 1 : 0);
        std::string threadFilename = baseFilename + "_thread_" + std::to_string(t) + ".txt";
        // Enqueue the task
        futures.emplace_back(pool.enqueue(generateRainbowTableChunk, start, end, threadFilename, passwordLength,
                                          chainLength));
        start = end;
    }

    for (auto &fut: futures) {
        fut.get();
    }
}

int main(int argc, char *argv[]) {
    WelcomeMessage::printRainbowMessage();

    if (argc < 4) {
        std::cerr << "Usage: ./rainbow [CHAIN_LENGTH] [TABLE_SIZE] [MIN_PWD_LENGTH] [OPTIONAL_MAX_PWD_LENGTH]\n";
        return EXIT_FAILURE;
    }

    // Parse command line arguments
    int chain_length = std::stoi(argv[1]);
    int table_size = std::stoi(argv[2]);
    int min_pwd_length = std::stoi(argv[3]);
    int max_pwd_length = min_pwd_length;
    if (argc >= 5) {
        max_pwd_length = std::stoi(argv[4]);
    }

    for (int pwd_length = min_pwd_length; pwd_length <= max_pwd_length; ++pwd_length) {
        std::cout << "[INFO] Generating rainbow table for password length: " << pwd_length << "\n";
        total_completed = 0;

        std::string baseFilename = "rainbow_table_length" + std::to_string(pwd_length);

        // Cleanup any leftover part files from previous runs
        std::cout << "[LOADING] Cleaning up...\n";
        for (const auto &entry: std::filesystem::directory_iterator(".")) {
            if (entry.is_regular_file()) {
                const std::string filename = entry.path().filename().string();
                if (filename.find(baseFilename + "_thread_") == 0) {
                    std::filesystem::remove(entry.path());
                }
            }
        }

        std::cout << "[SUCCESS] All clear!\n";
        std::cout << "[LOADING] Generating rainbow table, please wait...\n";

        // Start time measurement
        const auto start_time = std::chrono::high_resolution_clock::now();

        // Start the progress monitoring thread
        std::atomic<bool> progress_done(false);
        std::thread progress_thread([&]() {
            while (!progress_done) {
                const int64_t completed = total_completed.load();
                const double percentage = static_cast<double>(completed) / table_size * 100;
                std::cout << "\r[LOADING] Progress: " << std::fixed << std::setprecision(2) << percentage <<
                        "% completed." << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            // At the end, ensure progress shows 100%
            std::cout << "\r[LOADING] Completed." << std::endl;
        });

        // Generate the rainbow table for this password length
        generateRainbowTable(table_size, baseFilename, pwd_length, chain_length);

        // Indicate to progress thread that we're done
        progress_done = true;
        progress_thread.join();

        // End time measurement
        const auto end_time = std::chrono::high_resolution_clock::now();
        const std::chrono::duration<double> elapsed = end_time - start_time;

        std::cout << "\n[INFO] Rainbow table generated and stored in " << baseFilename << "_thread_*.txt\n";
        std::cout << "[INFO] Time taken to generate the rainbow table: " << elapsed.count() << " seconds.\n";
    }

    return 0;
}
