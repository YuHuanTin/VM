//
// Created by AFETT on 2024/8/25.
//

#ifndef RAPID_REGISTER_STRING_PARSER_H
#define RAPID_REGISTER_STRING_PARSER_H

/**
                                parse string like this

    RAX : 0000022DCDE011C0
    RBX : 0000000000000018
    RCX : 000000007FFE0380
    RDX : 0000000000000001
    RBP : 000000000000001A
    RSP : 000000A6EED6EFD0
    RSI : 0000022DCDE00D80
    RDI : 0000000000000018
    R8  : 0000022DCDE011C0
    R9  : 0000022DCDE01210
    R10 : 0000000000000000
    R11 : 000000A6EED6EC08
    R12 : 0000000000000001
    R13 : 0000000000000004
    R14 : 00007FF74D860000     v1_testexec.vmp2.00007FF74D860000
    R15 : 00007FF74DA24202     v1_testexec.vmp2.00007FF74DA24202
    RIP : 00007FF74D8868C3     v1_testexec.vmp2.00007FF74D8868C3
    RFLAGS : 0000000000000206     L'Ȇ'
    ZF : 0
    OF : 0
    CF : 0
    PF : 1
    SF : 0
    TF : 0     L'Ā'
    AF : 0
    DF : 0
    IF : 1
    LastError : 00000012 (ERROR_NO_MORE_FILES)
    LastStatus : C000000D (STATUS_INVALID_PARAMETER)
    GS : 002B
    ES : 002B
    CS : 0033
    FS : 0053
    DS : 002B
    SS : 002B
    DR0 : 00007FF74D861860     <v1_testexec.vmp2.mainCRTStartup>
    DR1 : 0000000000000000
    DR2 : 0000000000000000
    DR3 : 0000000000000000
    DR6 : 00000000FFFF4FF0
    DR7 : 0000000000000401     L'Ё'
*/

#include <string>

inline REGS ParseRegisterString(const std::string &Str) {
    REGS regs {};

    std::stringstream ss { Str };
    std::string       newLine;
    while (std::getline(ss, newLine, '\n')) {
        if (newLine.empty()) {
            continue;
        }

        const auto colonPos = newLine.find(':');
        if (colonPos == std::string::npos) {
            continue;
        }

        const auto registerName  = newLine.substr(0, newLine.find(' '));
        const auto registerValue = newLine.substr(newLine.find_first_not_of(' ', colonPos + 1), 16);
        if (registerName.empty() || registerValue.empty()) {
            continue;
        }

        const uint64_t value = std::stoull(registerValue, nullptr, 16);
        if (registerName == "RAX") {
            regs.rax_ = value;
        } else if (registerName == "RBX") {
            regs.rbx_ = value;
        } else if (registerName == "RCX") {
            regs.rcx_ = value;
        } else if (registerName == "RDX") {
            regs.rdx_ = value;
        } else if (registerName == "RBP") {
            regs.rbp_ = value;
        } else if (registerName == "RSP") {
            regs.rsp_ = value;
        } else if (registerName == "RSI") {
            regs.rsi_ = value;
        } else if (registerName == "RDI") {
            regs.rdi_ = value;
        } else if (registerName == "R8") {
            regs.r8_ = value;
        } else if (registerName == "R9") {
            regs.r9_ = value;
        } else if (registerName == "R10") {
            regs.r10_ = value;
        } else if (registerName == "R11") {
            regs.r11_ = value;
        } else if (registerName == "R12") {
            regs.r12_ = value;
        } else if (registerName == "R13") {
            regs.r13_ = value;
        } else if (registerName == "R14") {
            regs.r14_ = value;
        } else if (registerName == "R15") {
            regs.r15_ = value;
        } else if (registerName == "RIP") {
            regs.rip_ = value;
        } else if (registerName == "RFLAGS") {
            regs.rflags_ = value;
            break;
        }
    }

    return regs;
}


#endif //RAPID_REGISTER_STRING_PARSER_H
