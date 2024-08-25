//
// Created by AFETT on 2024/8/25.
//

#ifndef RAPID_MEMORY_DUMPER_H
#define RAPID_MEMORY_DUMPER_H

#include <utility>

#include "Windows.h"

/**
 * 自动 dump 程序指定范围所有内存到指定目录 
 */
class RipperMemoryDumper {
    struct HANDLE_DELETER {
        void operator()(const HANDLE handle) const {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
        }
    };

    using DecayedHandle = std::remove_pointer_t<HANDLE>;
    std::unique_ptr<DecayedHandle, HANDLE_DELETER> hProcess_;
    std::string                                    storageDirectory_;

public:
    RipperMemoryDumper(const uint64_t ProcessId, std::string StorageDirectory) : storageDirectory_(std::move(StorageDirectory)) {
        hProcess_ = std::unique_ptr<DecayedHandle, HANDLE_DELETER>(OpenProcess(PROCESS_ALL_ACCESS, true, ProcessId));

        const std::filesystem::path storageDirectory { storageDirectory_ };
        if (!exists(storageDirectory))
            create_directories(storageDirectory);
        if (!is_directory(storageDirectory))
            throw std::runtime_error("Not a directory");
        if (!is_empty(storageDirectory)) {
            remove_all(storageDirectory);
            create_directories(storageDirectory);
        }
    }

    void Dumper(const uint64_t Begin, const uint64_t Size) {
        std::vector<uint8_t> data(Size);
        uint64_t             read = 0;

        if (!ReadProcessMemory(hProcess_.get(), reinterpret_cast<LPVOID>(Begin), data.data(), Size, &read)) {
            std::println("Failed to read memory, GetLastError: {}, From: 0x{:016X}, Size: 0x{:016X}", GetLastError(), Begin, Size);
            return;
        }

        if (read != Size) {
            std::println("Failed to read memory, read: {} expected Size: {}", read, Size);
            return;
        }

        std::fstream fs { std::format("{}/ba{:016X}si{:016X}.bin", storageDirectory_, Begin, Size), std::ios::out | std::ios::binary };

        if (!fs.is_open()) {
            std::println("Failed to open file");
            return;
        }

        fs.write(reinterpret_cast<char *>(data.data()), Size);
    }

    void DumpMemory(const uint64_t Begin, const uint64_t End) {
        // 内存段信息
        MEMORY_BASIC_INFORMATION mbi;

        auto address = reinterpret_cast<LPVOID>(Begin);
        while (address < reinterpret_cast<LPVOID>(End)) {
            // 获取当前地址的内存段信息
            if (!VirtualQueryEx(hProcess_.get(), address, &mbi, sizeof(mbi))) {
                std::println("GetMemoryBasicInformation failed, {}", GetLastError());
                break;
            }
            // 跳过不可用的内存段
            if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE) {
                address = static_cast<LPVOID>(static_cast<LPBYTE>(address) + mbi.RegionSize);
                continue;
            }

            if (mbi.Protect & PAGE_GUARD) {
                if (!VirtualProtectEx(hProcess_.get(), mbi.BaseAddress, mbi.RegionSize, mbi.Protect & ~PAGE_GUARD, &mbi.Protect)) {
                    std::println("Failed to VirtualProtectEx, {}", GetLastError());
                }
            }

            switch (mbi.State) {
                case MEM_COMMIT:
                    Dumper(reinterpret_cast<uint64_t>(mbi.BaseAddress), mbi.RegionSize);
                    break;
                default:
                    std::println("unknow, {}", mbi.State);
            }

            // 移动到下一个内存段
            address = static_cast<LPVOID>(static_cast<LPBYTE>(address) + mbi.RegionSize);
        }
    }
};

#endif //RAPID_MEMORY_DUMPER_H
