//
// Created by AFETT on 2024/8/25.
//

#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE
#include <algorithm>
#include <chrono>
#include <print>
#include <ranges>
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>

#include "../Utils/Emulator.h"
#include "../Utils/RapidMemoryDumper.h"
#include "../Utils/RapidRegisterStringParser.h"


#define PROCESS_ID          14248
#define DUMP_FILE_DIR       "../../OEPTracker/DumpFile"
#define DUMP_BEGIN          0x000000007FFE0000
#define DUMP_END            0x00007FFF31432000
#define REGISTER_PARSER_STR R"(
RAX : 00007FFF312CDF50     <ntdll.NtProtectVirtualMemory>
RBX : 0000000000000000
RCX : FFFFFFFFFFFFFFFF
RDX : 0000000E1F78F540
RBP : 0000000E1F78F238     <&NtProtectVirtualMemory>
RSP : 0000000E1F78EFF8
RSI : 00007FF74DEFDA16     v1_testexec.vmp2.00007FF74DEFDA16
RDI : 0000000E1F78F238     <&NtProtectVirtualMemory>
R8  : 0000000E1F78F568     "痶5"
R9  : 0000000000000020     ' '
R10 : 33751117CA1A41DC
R11 : 0000000E1F78F280
R12 : 0000000015814A67
R13 : 0000000000000004
R14 : 0000000000000000
R15 : 00007FF74D860000     v1_testexec.vmp2.00007FF74D860000
RIP : 00007FF74DBBAB43     v1_testexec.vmp2.00007FF74DBBAB43
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
LastError : 000001E7 (ERROR_INVALID_ADDRESS)
LastStatus : C0000018 (STATUS_CONFLICTING_ADDRESSES)
GS : 002B
ES : 002B
CS : 0033
FS : 0053
DS : 002B
SS : 002B
DR0 : 00007FF74D861860     <v1_testexec.vmp2.mainCRTStartup>
DR1 : 00007FFF312CDF50     <ntdll.NtProtectVirtualMemory>
DR2 : 0000000000000000
DR3 : 0000000000000000
DR6 : 00000000FFFF4FF0
DR7 : 0000000000000405     L'Ѕ'

)"

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));


    RipperMemoryDumper rip(PROCESS_ID, DUMP_FILE_DIR);
    rip.DumpMemory(DUMP_BEGIN, DUMP_END);

    X64Emulator emulator { ParseRegisterString(REGISTER_PARSER_STR) };
    emulator.RegisterObserver(0, [](X64Emulator *Emu) {
        uint8_t code[32];
        CHECK_ERR(uc_mem_read(Emu->uc_, Emu->regs_.rip_, code, 32));
        ZydisDisassembledInstruction insn;
        ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Emu->regs_.rip_, code, 32, &insn);
        if (Emu->regs_.rip_ >= 0x00007FFF054B0000) {
            std::print("External Call RIP: ");
        }
        std::println("0x{:016x}, {}", insn.runtime_address, insn.text);
    });

    emulator.RegisterObserver(0x00007FF74D861860, [](X64Emulator *Emu) {
        std::println("RIP: 0x{:016X}", Emu->regs_.rip_);
    });

    const auto startTimePoint = std::chrono::system_clock::now();
    try {
        emulator.LoadSegments(DUMP_FILE_DIR);
        emulator.Run();
    } catch (std::exception &Exception) {
        std::println("Exception: {}", Exception.what());
    }

    std::println("Time elapsed: {}ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - startTimePoint).count());
}
