/*
* File: attack.cpp
*
* Authors: Gardeur Nicolas, Hennen Cyril, Ishimwe Daniel, Meunier Arnaud
* Created: 13th of October 2024
* Source: https://gitlab.com/info-y115/rainbow-table
*
* Description:
* This file contains the implementation for cracking SHA-256 hashes using a 
* rainbow table attack. It supports both portable SHA-256 and optimized versions 
* utilizing x64 intrinsics or ARM Cryptography Extensions depending on the 
* architecture. The reduction function and parallelism through thread pooling 
* are key features for improving the cracking speed.
*
*/

#include "./utils/welcome.hpp"
#include "./utils/threadpool.hpp"
#include "constants.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <thread>
#include <array>
#include <future>
#include <filesystem>

#if defined(USE_PORTABLE_SHA256)
#include "./utils/sha256_portable.h"
#else
#if defined(__x86_64__) || defined(_M_X64)

#endif
#include "./utils/sha256.h"
#endif


// Define HashType
using HashType = std::array<uint8_t, 32>;
using PswCodeFormat = std::array<uint8_t, 10>;
constexpr size_t MAX_PASSWORD_LENGTH = 20;

// Define TargetHashInfo struct to keep track of cracked passwords
struct TargetHashInfo {
    HashType hash;
    std::string crackedPassword; // Empty if not yet cracked
};

// Function to convert hex string to HashType
inline uint8_t hexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    else if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    else if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    else return 0;
}

HashType hexStringToBytes(const std::string &hexStr) {
    HashType bytes;
    size_t len = hexStr.length();
    for (size_t i = 0; i < len / 2; ++i) {
        uint8_t high = hexCharToValue(hexStr[2 * i]);
        uint8_t low = hexCharToValue(hexStr[2 * i + 1]);
        bytes[i] = (high << 4) | low;
    }
    return bytes;
}

// Function to convert HashType to hex string
std::string bytesToHexString(const HashType &bytes) {
    static const char *hexDigits = "0123456789abcdef";
    std::string hexStr;
    hexStr.reserve(64);
    for (uint8_t byte: bytes) {
        hexStr.push_back(hexDigits[byte >> 4]);
        hexStr.push_back(hexDigits[byte & 0x0F]);
    }
    return hexStr;
}

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

// Reduction function
static std::string reduce(const HashType &hashBytes, int reductionIndex, size_t passwordLength) {
    std::string password;
    password.reserve(passwordLength);
    const size_t hashLength = hashBytes.size();

    for (size_t i = 0; i < passwordLength; ++i) {
        password += CHARSET[hashBytes[(reductionIndex + i * 7) % hashLength] % CHARSET.size()];
    }

    return password;
}

static std::vector<TargetHashInfo> loadPasswordToCrack(const std::string &hashToCrackFilePath) {
    std::ifstream inputFile(hashToCrackFilePath);
    if (!inputFile.is_open()) {
        std::cerr << "[ERROR] Error opening input file.\n";
        exit(EXIT_FAILURE);
    }
    std::cout << "[SUCCESS] Rainbow table initialized successfully!\n";

    std::vector<TargetHashInfo> targetHashes;
    targetHashes.reserve(100);
    std::string targetHashStr;

    while (std::getline(inputFile, targetHashStr)) {
        targetHashStr.erase(std::remove_if(targetHashStr.begin(), targetHashStr.end(), ::isspace), targetHashStr.end());

        if (targetHashStr.empty()) continue; // Skip empty lines

        if (targetHashStr.length() != 64) {
            // SHA-256 hashes are 64 hex characters
            std::cerr << "[ERROR] Invalid SHA-256 hash length: " << targetHashStr <<
                    ". Expected 64 hexadecimal characters.\n";
            continue;
        }
        HashType targetHash = hexStringToBytes(targetHashStr);
        targetHashes.push_back({targetHash, ""});
    }
    inputFile.close();

    if (targetHashes.empty()) {
        std::cerr << "[ERROR] No valid hashes found in input file.\n";
        exit(EXIT_FAILURE);
    }

    return targetHashes;
}

static std::string regeneratePsw(std::string head, const int numberOfRounds, const int matchIndex) {
    const int roundsToRegenerate = numberOfRounds - matchIndex - 1;
    const size_t headSize = head.size();

    if (roundsToRegenerate == -1) {
        return head;
    }

    std::string currentPsw = reduce(sha256_raw(head.c_str(), headSize), 0, headSize);
    for (int i = 1; i < roundsToRegenerate; ++i) {
        currentPsw = reduce(sha256_raw(&currentPsw, headSize), i, headSize);
    }

    return currentPsw;
}

// Function to process each target hash in a separate thread
void processTargetHash(TargetHashInfo &hashInfo, int chain_length, int num_threads, std::ofstream &outputFile) {
    if (!hashInfo.crackedPassword.empty()) {
        return;
    }

    for (int pwd_length = 6; pwd_length <= 10; ++pwd_length) {
        std::string baseFilename = "rainbow_table_length" + std::to_string(pwd_length) + "_thread_";

        // Detect available rainbow table files for this password length
        std::vector<std::string> rainbowFiles;
        for (int i = 0; i < num_threads; ++i) {
            std::string filename = baseFilename + std::to_string(i) + ".txt";
            if (std::filesystem::exists(filename)) {
                rainbowFiles.push_back(filename);
            }
        }

        if (rainbowFiles.empty()) {
            continue;
        }

        for (const auto &tableFile: rainbowFiles) {
            // For chain_index from chain_length -1 down to 0
            for (int t = chain_length - 1; t >= 0; --t) {
                std::string pwd = reduce(hashInfo.hash, t, pwd_length);

                // Build chain from position t+1 to chain_length
                std::string tempPwd = pwd;
                for (int j = t + 1; j < chain_length; ++j) {
                    HashType hashBytes = sha256_raw(tempPwd.c_str(), pwd_length);
                    tempPwd = reduce(hashBytes, j, pwd_length);
                }

                // Now tempPwd is a possible tail. Check if tempPwd matches any tail in the rainbow table file
                std::ifstream rainbowTableFile(tableFile);
                if (!rainbowTableFile.is_open()) {
                    std::cerr << "[ERROR] Error opening rainbow table file: " << tableFile << "\n";
                    continue;
                }

                std::string fileLine;
                while (std::getline(rainbowTableFile, fileLine)) {
                    if (fileLine.length() < 2 * pwd_length + 1) continue; // Invalid line
                    std::string head = fileLine.substr(0, pwd_length);
                    std::string tail = fileLine.substr(pwd_length + 1, pwd_length);

                    if (tempPwd == tail) {
                        // Regenerate password starting from head
                        std::string currentPwd = head;
                        for (int k = 0; k < chain_length; ++k) {
                            if (sha256_raw(currentPwd.c_str(), pwd_length) == hashInfo.hash) {
                                hashInfo.crackedPassword = currentPwd;
                                outputFile << bytesToHexString(hashInfo.hash) << " : " << hashInfo.crackedPassword << "\n";
                                return;
                            }
                            HashType hashBytes = sha256_raw(currentPwd.c_str(), pwd_length);
                            currentPwd = reduce(hashBytes, k, pwd_length);
                        }
                    }
                }

                rainbowTableFile.close();
            }
        }
    }
}

int main(int argc, char *argv[]) {
    WelcomeMessage::printAttackMessage();

    if (argc < 3) {
        std::cerr << "Usage: ./attack [HASHES.txt] [CHAIN_LENGTH]\n";
        return EXIT_FAILURE;
    }

    std::string inputFileName = argv[1];
    int chain_length = std::stoi(argv[2]);
    std::vector<TargetHashInfo> targetHashes = loadPasswordToCrack(inputFileName);

    // Open the output file
    std::string outputFileName = "output_passwords.txt";
    std::ofstream outputFile(outputFileName);

    if (!outputFile.is_open()) {
        std::cerr << "[ERROR] Error opening output file.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[LOADING] Cracking passwords... please wait" << std::endl << std::flush;;
    // Create ThreadPool
    int num_threads = static_cast<int>(std::thread::hardware_concurrency());
    if (num_threads == 0) num_threads = 4;
    ThreadPool pool(num_threads);

    std::vector<std::string> prefixFiles;
    for (int i = 0; i < num_threads; ++i) {
        std::string prefixFilename = "rainbow_table_length" + std::to_string(i) + ".txt";
        if (std::filesystem::exists(prefixFilename)) {
            prefixFiles.push_back(prefixFilename);
        }
    }

    // Process each target hash in parallel
    std::vector<std::future<void> > futures;
    for (auto &hashInfo: targetHashes) {
        futures.emplace_back(pool.enqueue([&hashInfo, chain_length, num_threads, &outputFile]() {
            processTargetHash(hashInfo, chain_length, num_threads, outputFile);
        }));
    }

    // Wait for all threads to finish
    for (auto &future: futures) {
        future.get();
    }

    outputFile.close();

    std::ofstream outputFileFinal(outputFileName, std::ofstream::trunc);

    // Write results to output file
    for (const auto &hashInfo: targetHashes) {
        if (hashInfo.crackedPassword.empty()) {
            outputFileFinal << bytesToHexString(hashInfo.hash) << " : ?\n";
        } else {
            outputFileFinal << bytesToHexString(hashInfo.hash) << " : " << hashInfo.crackedPassword << "\n";
        }
    }

    // Close the output file
    outputFileFinal.close();

    std::cout << "[SUCCESS] Password cracking completed. Results written to " << outputFileName << "\n";

    return 0;
}
