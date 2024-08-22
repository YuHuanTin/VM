//
// Created by AFETT on 2024/8/21.
//

#ifndef DEF_H
#define DEF_H

#include <cstdint>
#include <fstream>
#include <string_view>

#include <Zydis/Zydis.h>
#include <nameof.hpp>

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
//
// struct REGS_DECOMPOSE {
// #if ARCHITECTURE == ARCHITECTURE_X64
//     uint8_t al;
//     uint8_t ah;
//     uint8_t ax;
//     uint8_t eax;
//     uint8_t rax;
//
//     uint8_t bl;
//     uint8_t bh;
//     uint8_t bx;
//     uint8_t ebx;
//     uint8_t rbx;
//
//     uint8_t cl;
//     uint8_t ch;
//     uint8_t cx;
//     uint8_t ecx;
//     uint8_t rcx;
//
//     uint8_t dl;
//     uint8_t dh;
//     uint8_t dx;
//     uint8_t edx;
//     uint8_t rdx;
//
//     uint8_t bpl;
//     uint8_t bp;
//     uint8_t ebp;
//     uint8_t rbp;
//
//     uint8_t spl;
//     uint8_t sp;
//     uint8_t esp;
//     uint8_t rsp;
//
//     uint8_t sil;
//     uint8_t si;
//     uint8_t esi;
//     uint8_t rsi;
//
//     uint8_t dil;
//     uint8_t di;
//     uint8_t edi;
//     uint8_t rdi;
//
//     uint8_t r8b;
//     uint8_t r8w;
//     uint8_t r8d;
//     uint8_t r8;
//
//     uint8_t r9b;
//     uint8_t r9w;
//     uint8_t r9d;
//     uint8_t r9;
//
//     uint8_t r10b;
//     uint8_t r10w;
//     uint8_t r10d;
//     uint8_t r10;
//
//     uint8_t r11b;
//     uint8_t r11w;
//     uint8_t r11d;
//     uint8_t r11;
//
//     uint8_t r12b;
//     uint8_t r12w;
//     uint8_t r12d;
//     uint8_t r12;
//
//     uint8_t r13b;
//     uint8_t r13w;
//     uint8_t r13d;
//     uint8_t r13;
//
//     uint8_t r14b;
//     uint8_t r14w;
//     uint8_t r14d;
//     uint8_t r14;
//
//     uint8_t r15b;
//     uint8_t r15w;
//     uint8_t r15d;
//     uint8_t r15;
//
//     uint8_t ip;
//     uint8_t eip;
//     uint8_t rip;
//
//     uint8_t flags;
//     uint8_t eflags;
//     uint8_t rflags;
//
//     
//
//     std::string ToString() const {
//         auto formatOutput = [](uint8_t Reg, std::string_view RegName) {
//             if (Reg & ZydisOperandAction::ZYDIS_OPERAND_ACTION_MASK_READ && Reg & ZydisOperandAction::ZYDIS_OPERAND_ACTION_MASK_WRITE) {
//                 // 默认先读后写？
//                 return std::format("{:<6s}: rw, ", RegName);
//             } else if (Reg & ZydisOperandAction::ZYDIS_OPERAND_ACTION_MASK_WRITE) {
//                 return std::format("{:<6s}: w , ", RegName);
//             } else if (Reg & ZYDIS_OPERAND_ACTION_MASK_READ) {
//                 return std::format("{:<6s}: r , ", RegName);
//             } else {
//                 return std::string {};
//             }
//         };
//         
//         return formatOutput(al, NAMEOF(al)) + formatOutput(ah, NAMEOF(ah)) + formatOutput(ax, NAMEOF(ax)) + formatOutput(eax, NAMEOF(eax)) + formatOutput(rax, NAMEOF(rax)) +
//                formatOutput(bl, NAMEOF(bl)) + formatOutput(bh, NAMEOF(bh)) + formatOutput(bx, NAMEOF(bx)) + formatOutput(ebx, NAMEOF(ebx)) + formatOutput(rbx, NAMEOF(rbx)) +
//                formatOutput(cl, NAMEOF(cl)) + formatOutput(ch, NAMEOF(ch)) + formatOutput(cx, NAMEOF(cx)) + formatOutput(ecx, NAMEOF(ecx)) + formatOutput(rcx, NAMEOF(rcx)) +
//                formatOutput(dl, NAMEOF(dl)) + formatOutput(dh, NAMEOF(dh)) + formatOutput(dx, NAMEOF(dx)) + formatOutput(edx, NAMEOF(edx)) + formatOutput(rdx, NAMEOF(rdx)) +
//                formatOutput(bpl, NAMEOF(bpl)) + formatOutput(bp, NAMEOF(bp)) + formatOutput(ebp, NAMEOF(ebp)) + formatOutput(rbp, NAMEOF(rbp)) +
//                formatOutput(spl, NAMEOF(spl)) + formatOutput(sp, NAMEOF(sp)) + formatOutput(esp, NAMEOF(esp)) + formatOutput(rsp, NAMEOF(rsp)) +
//                formatOutput(sil, NAMEOF(sil)) + formatOutput(si, NAMEOF(si)) + formatOutput(esi, NAMEOF(esi)) + formatOutput(rsi, NAMEOF(rsi)) +
//                formatOutput(dil, NAMEOF(dil)) + formatOutput(di, NAMEOF(di)) + formatOutput(edi, NAMEOF(edi)) + formatOutput(rdi, NAMEOF(rdi)) +
//                formatOutput(r8b, NAMEOF(r8b)) + formatOutput(r8w, NAMEOF(r8w)) + formatOutput(r8d, NAMEOF(r8d)) + formatOutput(r8, NAMEOF(r8)) +
//                formatOutput(r9b, NAMEOF(r9b)) + formatOutput(r9w, NAMEOF(r9w)) + formatOutput(r9d, NAMEOF(r9d)) + formatOutput(r9, NAMEOF(r9)) +
//                formatOutput(r10b, NAMEOF(r10b)) + formatOutput(r10w, NAMEOF(r10w)) + formatOutput(r10d, NAMEOF(r10d)) + formatOutput(r10, NAMEOF(r10)) +
//                formatOutput(r11b, NAMEOF(r11b)) + formatOutput(r11w, NAMEOF(r11w)) + formatOutput(r11d, NAMEOF(r11d)) + formatOutput(r11, NAMEOF(r11)) +
//                formatOutput(r12b, NAMEOF(r12b)) + formatOutput(r12w, NAMEOF(r12w)) + formatOutput(r12d, NAMEOF(r12d)) + formatOutput(r12, NAMEOF(r12)) +
//                formatOutput(r13b, NAMEOF(r13b)) + formatOutput(r13w, NAMEOF(r13w)) + formatOutput(r13d, NAMEOF(r13d)) + formatOutput(r13, NAMEOF(r13)) +
//                formatOutput(r14b, NAMEOF(r14b)) + formatOutput(r14w, NAMEOF(r14w)) + formatOutput(r14d, NAMEOF(r14d)) + formatOutput(r14, NAMEOF(r14)) +
//                formatOutput(r15b, NAMEOF(r15b)) + formatOutput(r15w, NAMEOF(r15w)) + formatOutput(r15d, NAMEOF(r15d)) + formatOutput(r15, NAMEOF(r15)) +
//                formatOutput(ip, NAMEOF(ip)) + formatOutput(eip, NAMEOF(eip)) + formatOutput(rip, NAMEOF(rip)) +
//                formatOutput(flags, NAMEOF(flags)) + formatOutput(eflags, NAMEOF(eflags)) + formatOutput(rflags, NAMEOF(rflags));
//     }
// #elif ARCHITECTURE == ARCHITECTURE_X86
//     uint8_t  al;
//     uint8_t  ah;
//     uint16_t ax;
//     uint32_t eax;
//
//     uint8_t  bl;
//     uint8_t  bh;
//     uint16_t bx;
//     uint32_t ebx;
//
//     uint8_t  cl;
//     uint8_t  ch;
//     uint16_t cx;
//     uint32_t ecx;
//
//     uint8_t  dl;
//     uint8_t  dh;
//     uint16_t dx;
//     uint32_t edx;
//
//     uint8_t  bpl;
//     uint16_t bp;
//     uint32_t ebp;
//
//     uint8_t  spl;
//     uint16_t sp;
//     uint32_t esp;
//
//     uint8_t  sil;
//     uint16_t si;
//     uint32_t esi;
//
//     uint8_t  dil;
//     uint16_t di;
//     uint32_t edi;
//
//     uint16_t ip;
//     uint32_t eip;
//
//     uint16_t flags;
//     uint32_t eflags;
// #endif
// };

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
