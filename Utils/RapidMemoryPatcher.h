//
// Created by AFETT on 2024/9/1.
//

#ifndef RAPIDMEMORYPATCHER_H
#define RAPIDMEMORYPATCHER_H


#include <print>
#include <span>
#include <ranges>
#include <algorithm>

#include "Windows.h"

class RipperMemoryPatcher {
    struct HANDLE_DELETER {
        void operator()(const HANDLE handle) const {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
        }
    };

    using DecayedHandle = std::remove_pointer_t<HANDLE>;
    std::unique_ptr<DecayedHandle, HANDLE_DELETER> hProcess_;

public:
    explicit RipperMemoryPatcher(const uint64_t ProcessId) {
        hProcess_ = std::unique_ptr<DecayedHandle, HANDLE_DELETER>(OpenProcess(PROCESS_ALL_ACCESS, true, ProcessId));
    }


    void Patcher(const uint64_t Begin, const uint64_t Size, std::span<uint8_t> Pattern = {}, std::span<uint8_t> Replace = {}) const {
        if (Pattern.size() != Replace.size()) {
            std::println("PatcherMemory: Pattern.size() != Replace.size()");
            return;
        }

        std::vector<uint8_t> buffer;
        if (Size > 0x1000 * 0x1000) {
            // about 16KB
            buffer.resize(0x1000 * 0x1000);
        } else {
            buffer.resize(Size);
        }
        uint64_t pos = Begin;
        while (pos < Size + Begin) {
            uint64_t n = 0;
            if (!ReadProcessMemory(hProcess_.get(), reinterpret_cast<LPVOID>(pos), buffer.data(), buffer.size(), &n)) {
                std::println("ReadProcessMemory failed, {}", GetLastError());
                break;
            }
            if (n != buffer.size()) {
                std::println("ReadProcessMemory n != buffer.size, {}", GetLastError());
                break;
            }
            buffer.resize(n);

            // replace from pattern to replace
            for (;;) {
                auto found = std::ranges::search(buffer, Pattern);
                if (found.empty()) {
                    break;
                }
                std::ranges::copy(Replace, found.begin());
            }

            if (!WriteProcessMemory(hProcess_.get(), reinterpret_cast<LPVOID>(pos), buffer.data(), buffer.size(), &n)) {
                std::println("WriteProcessMemory failed, {}", GetLastError());
                break;
            }

            if (n != buffer.size()) {
                std::println("WriteProcessMemory n != buffer.size, {}", GetLastError());
                break;
            }

            pos += n;
        }
    }

    void PatcherMemory(const uint64_t Begin, const uint64_t End, std::span<uint8_t> Pattern = {}, std::span<uint8_t> Replace = {}) {
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
                    Patcher(reinterpret_cast<uint64_t>(mbi.BaseAddress), mbi.RegionSize, Pattern, Replace);
                    break;
                default:
                    std::println("unknow, {}", mbi.State);
            }

            // 移动到下一个内存段
            address = static_cast<LPVOID>(static_cast<LPBYTE>(address) + mbi.RegionSize);
        }
    }
};

#endif //RAPIDMEMORYPATCHER_H
