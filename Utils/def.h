//
// Created by AFETT on 2024/8/21.
//

#ifndef DEF_H
#define DEF_H

#include <cstdint>
#include <fstream>
#include <map>
#include <string_view>

#include <nameof.hpp>
#include <Zydis/Zydis.h>

struct SEG_MAP {
    uint64_t         base_;
    uint64_t         size_;
    std::string_view file_name_;
};

struct SEG_MAP_X86 {
    uint32_t         base_;
    uint32_t         size_;
    std::string_view file_name_;
};

struct SEG_MAP_MEM {
    uint64_t    base_;
    uint64_t    size_;
    std::string buffer_;
};

struct SEG_MAP_MEM_X86 {
    uint32_t    base_;
    uint32_t    size_;
    std::string buffer_;
};

struct REGS {
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
};

struct REGS_X86 {
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
};

namespace REGISTER_ORDER {
    enum RegisterType {
        // general registers
        TypeAX, TypeBX, TypeCX, TypeDX,
        // segment registers
        TypeBP, TypeSP, TypeSI, TypeDI,
        // extra registers
        TypeR8, TypeR9, TypeR10, TypeR11, TypeR12, TypeR13, TypeR14, TypeR15,
        // ip and flags
        TypeIP, TypeFLAGS,
    };

    // Use a constexpr array to define register groups
    constexpr std::array<std::array<ZydisRegister, 5>, 4> GeneralRegister = {
        {
            { ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_AX, ZYDIS_REGISTER_AH, ZYDIS_REGISTER_AL },
            { ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_EBX, ZYDIS_REGISTER_BX, ZYDIS_REGISTER_BH, ZYDIS_REGISTER_BL },
            { ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_CX, ZYDIS_REGISTER_CH, ZYDIS_REGISTER_CL },
            { ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_DX, ZYDIS_REGISTER_DH, ZYDIS_REGISTER_DL }
        }
    };

    constexpr std::array<std::array<ZydisRegister, 4>, 4> SegmentRegister = {
        {
            { ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_BP, ZYDIS_REGISTER_BPL },
            { ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_SP, ZYDIS_REGISTER_SPL },
            { ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_SI, ZYDIS_REGISTER_SIL },
            { ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_EDI, ZYDIS_REGISTER_DI, ZYDIS_REGISTER_DIL }
        }
    };

    constexpr std::array<std::array<ZydisRegister, 4>, 8> ExtraRegister = {
        {
            { ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R8D, ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_R8B },
            { ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R9D, ZYDIS_REGISTER_R9W, ZYDIS_REGISTER_R9B },
            { ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R10B },
            { ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_R11W, ZYDIS_REGISTER_R11B },
            { ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_R12B },
            { ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R13B },
            { ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R14B },
            { ZYDIS_REGISTER_R15, ZYDIS_REGISTER_R15D, ZYDIS_REGISTER_R15W, ZYDIS_REGISTER_R15B }
        }
    };

    constexpr std::array IpRegister = {
        ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_EIP, ZYDIS_REGISTER_IP
    };

    constexpr std::array FlagRegister = {
        ZYDIS_REGISTER_RFLAGS, ZYDIS_REGISTER_EFLAGS, ZYDIS_REGISTER_FLAGS
    };

    std::map<ZydisRegister, RegisterType>               RegToType;
    std::map<RegisterType, std::vector<ZydisRegister> > TypeToReg;

    // Initialize maps at compile time
    inline void InitializeMaps() {
        for (size_t i = 0; i < GeneralRegister.size(); ++i) {
            TypeToReg[static_cast<RegisterType>(i)] = std::vector(GeneralRegister[i].begin(), GeneralRegister[i].end());
            for (auto reg: GeneralRegister[i]) {
                RegToType[reg] = static_cast<RegisterType>(i);
            }
        }
        for (size_t i = 0; i < SegmentRegister.size(); ++i) {
            TypeToReg[static_cast<RegisterType>(i + 4)] = std::vector<ZydisRegister>(SegmentRegister[i].begin(), SegmentRegister[i].end());
            for (auto reg: SegmentRegister[i]) {
                RegToType[reg] = static_cast<RegisterType>(i + 4);
            }
        }
        for (size_t i = 0; i < ExtraRegister.size(); ++i) {
            TypeToReg[static_cast<RegisterType>(i + 8)] = std::vector<ZydisRegister>(ExtraRegister[i].begin(), ExtraRegister[i].end());
            for (auto reg: ExtraRegister[i]) {
                RegToType[reg] = static_cast<RegisterType>(i + 8);
            }
        }
        TypeToReg[TypeIP] = std::vector<ZydisRegister>(IpRegister.begin(), IpRegister.end());
        for (auto reg: IpRegister) {
            RegToType[reg] = TypeIP;
        }
        TypeToReg[TypeFLAGS] = std::vector<ZydisRegister>(FlagRegister.begin(), FlagRegister.end());
        for (auto reg: FlagRegister) {
            RegToType[reg] = TypeFLAGS;
        }
    }
} // namespace REGISTER_ORDER

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
