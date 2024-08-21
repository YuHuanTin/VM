//
// Created by AFETT on 2024/8/21.
//

#ifndef DEF_H
#define DEF_H

#include <cstdint>
#include <fstream>
#include <string_view>

#define ARCHITECTURE_X86 0
#define ARCHITECTURE_X64 1

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#if defined(__x86_64__) || defined(_M_X64)
#define ARCHITECTURE ARCHITECTURE_X64
#elif defined(__i386) || defined(_M_IX86)
#define ARCHITECTURE ARCHITECTURE_X86
#endif
#else
#error "Unsupported architecture"
#endif


struct SEG_MAP {
#if ARCHITECTURE == ARCHITECTURE_X64
    uint64_t base_;
    uint64_t size_;
#elif ARCHITECTURE == ARCHITECTURE_X86
    uint32_t         base_;
    uint32_t         size_;
#endif
    std::string_view file_name_;
};

struct REGS {
#if ARCHITECTURE == ARCHITECTURE_X64
    uint64_t rax_;
    uint64_t rbx_;
    uint64_t rcx_;
    uint64_t rdx_;
    uint64_t rbp_;
    uint64_t rsp_;
    uint64_t rsi_;
    uint64_t rdi_;
    uint64_t r8_;
    uint64_t r9_;
    uint64_t r10_;
    uint64_t r11_;
    uint64_t r12_;
    uint64_t r13_;
    uint64_t r14_;
    uint64_t r15_;
    uint64_t rip_;
    uint64_t rflags_;
#elif ARCHITECTURE == ARCHITECTURE_X86
    uint32_t eax_;
    uint32_t ebx_;
    uint32_t ecx_;
    uint32_t edx_;
    uint32_t ebp_;
    uint32_t esp_;
    uint32_t esi_;
    uint32_t edi_;
    uint32_t eip_;
    uint32_t eflags_;
#endif
};

#define CHECK_ERR(EXPRESSION) \
    if (auto RETURN_VALUE = (EXPRESSION); RETURN_VALUE != UC_ERR_OK) { \
        throw std::runtime_error(std::format("Failed on uc_{} with error returned: {}", __func__, static_cast<unsigned int>(RETURN_VALUE))); \
    }

inline std::string ReadFileBinary(std::string_view FileName) {
    std::fstream fs { FileName.data(), std::ios::in | std::ios::binary };
    fs.seekg(0, std::ios::end);
    const auto length = fs.tellg();
    fs.seekg(0, std::ios::beg);

    std::string buf(length, '\0');
    fs.read(&buf[0], length);
    return buf;
}

#endif //DEF_H
