#include "system-info.hpp"
#include <iostream>
#include <string>
#include <thread>
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <sysinfoapi.h>
#include <vector>
#elif defined(__linux__)
    #include <sys/sysinfo.h>
    #include <fstream>
#elif defined(__APPLE__) || defined(__MACH__)
    #include <sys/types.h>
    #include <sys/sysctl.h>
#endif

std::string getOSName() {
    try {
#if defined(_WIN32) || defined(_WIN64)
        return "Windows";
#elif defined(__linux__)
        std::ifstream file("/etc/os-release");
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("PRETTY_NAME=") != std::string::npos) {
                return line.substr(13, line.size() - 14);  // Strip the quotes
            }
        }
        return "Linux";
#elif defined(__APPLE__) || defined(__MACH__)
        return "macOS";
#else
        return "undefined";
#endif
    } catch (...) {
        return "undefined";
    }
}

std::string getProcessorName() {
    try {
#if defined(_WIN32) || defined(_WIN64)
        try {
            // Retrieve CPU name from the registry
            HKEY hKeyProcessor;
            const char *subkey = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKeyProcessor) != ERROR_SUCCESS) {
                throw std::runtime_error("Failed to open registry key.");
            }

            char cpuName[256] = {0}; // Initialize with null terminators to avoid garbage data
            DWORD bufferSize = sizeof(cpuName);
            if (RegQueryValueExA(hKeyProcessor, "ProcessorNameString", NULL, NULL, (LPBYTE) cpuName, &bufferSize) !=
                ERROR_SUCCESS) {
                RegCloseKey(hKeyProcessor);
                throw std::runtime_error("Failed to query CPU name.");
            }
            RegCloseKey(hKeyProcessor);

            // Get system architecture and thread count
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            int numThreads = static_cast<int>(std::thread::hardware_concurrency());

            std::string architecture;
            if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                architecture = "x64";
            } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
                architecture = "ARM";
            } else {
                architecture = "undefined";
            }

            // Return CPU name with architecture and thread count
            return std::string(cpuName) + " | Architecture: " + architecture + " | Threads: " + std::to_string(
                       numThreads);
        } catch (...) {
            // Fallback in case of any failure
            return "Architecture: x64 | Threads: " + std::to_string(std::thread::hardware_concurrency());
        }
#elif defined(__linux__)
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        std::string modelName;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                modelName = line.substr(line.find(":") + 2);
            }
        }

        if (modelName.empty()) return "undefined";

        int numLogicalProcessors = static_cast<int>(std::thread::hardware_concurrency());
        struct sysinfo info;
        sysinfo(&info);
        int numPhysicalCores = get_nprocs_conf();

        return modelName + " | Cores: " + std::to_string(numPhysicalCores) + " | Threads: " + std::to_string(numLogicalProcessors);

#elif defined(__APPLE__) || defined(__MACH__)
        char buffer[128];
        size_t size = sizeof(buffer);
        sysctlbyname("machdep.cpu.brand_string", &buffer, &size, NULL, 0);
        std::string cpuBrand = std::string(buffer);

        // Getting the number of physical cores
        int numPhysicalCores;
        size = sizeof(numPhysicalCores);
        sysctlbyname("hw.physicalcpu", &numPhysicalCores, &size, NULL, 0);

        // Getting the number of logical processors
        int numLogicalProcessors;
        size = sizeof(numLogicalProcessors);
        sysctlbyname("hw.logicalcpu", &numLogicalProcessors, &size, NULL, 0);

        return cpuBrand + " | Cores: " + std::to_string(numPhysicalCores) + " | Threads: " + std::to_string(numLogicalProcessors);

#else
        return "undefined";
#endif
    } catch (...) {
        return "undefined";
    }
}

std::string getRAMSize() {
    try {
#if defined(_WIN32) || defined(_WIN64)
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        GlobalMemoryStatusEx(&status);
        return std::to_string(status.ullTotalPhys / (1024 * 1024)) + " MB";
#elif defined(__linux__)
        struct sysinfo info;
        if (sysinfo(&info) == 0) {
            return std::to_string(info.totalram * info.mem_unit / (1024 * 1024)) + " MB";
        } else {
            return "undefined";
        }
#elif defined(__APPLE__) || defined(__MACH__)
        int64_t ram;
        size_t len = sizeof(ram);
        if (sysctlbyname("hw.memsize", &ram, &len, NULL, 0) == 0) {
            return std::to_string(ram / (1024 * 1024)) + " MB";
        } else {
            return "undefined";
        }
#else
        return "undefined";
#endif
    } catch (...) {
        return "undefined";
    }
}
