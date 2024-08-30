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


#define PROCESS_ID          11072
#define DUMP_FILE_DIR       "../../EmulatorTest/DumpFile"
#define DUMP_BEGIN          0x0000000000400000
#define DUMP_END            0x0000000000790000
#define REGISTER_PARSER_STR R"(
RAX : 0000000000130000
RBX : 0000000000000040     '@'
RCX : 000000000065F0F0
RDX : 00000000B1130C18
RBP : 0000000000000023     '#'
RSP : 000000000065F070     "(馜"
RSI : 0000000000792F20
RDI : 0000000000000000
R8  : 0000000003000201
R9  : 0000000000000000
R10 : 0000000000000000
R11 : 000000000065EC30
R12 : 000000000079A4A0     "11223344556677889900112233445566"
R13 : 0000000000000023     '#'
R14 : 0000000000442D60     k.0000000000442D60
R15 : 000000000000002C     ','
RIP : 000000000040C602     k.000000000040C602
RFLAGS : 0000000000000284     L'ʄ'
ZF : 0
OF : 0
CF : 0
PF : 1
SF : 1
TF : 0
AF : 0
DF : 0
IF : 1
LastError : 00000000 (ERROR_SUCCESS)
LastStatus : C000000D (STATUS_INVALID_PARAMETER)
GS : 002B
ES : 002B
CS : 0033
FS : 0053
DS : 002B
SS : 002B
DR0 : 00000000000C2F20
DR1 : 00000000000CA4A0
DR2 : 0000000000000000
DR3 : 0000000000000000
DR6 : 0000000000000000
DR7 : 0000000000BF0005

)"

void cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    if (size >= 8) {
        return;
    }
    uint32_t data = 0;
    uc_mem_read(uc, address, &data, size);

    std::println("callback, type={:<12}, addr=0x{:016X}, data={:08X}, size={}, value={:08X}", NAMEOF_ENUM(type), address, data, size, value);

    auto v = static_cast<X64Emulator *>(user_data);
    v->PrintRegs();
}

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));

    // RipperMemoryDumper rip(PROCESS_ID, DUMP_FILE_DIR);
    // rip.DumpMemory(DUMP_BEGIN, DUMP_END);

    X64Emulator emulator { ParseRegisterString(REGISTER_PARSER_STR) };
    emulator.RegisterObserver(0, [](X64Emulator *Emu) {
        uint8_t code[32];
        CHECK_ERR(uc_mem_read(Emu->uc_, Emu->regs_.rip_, code, 32));
        ZydisDisassembledInstruction insn;
        ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Emu->regs_.rip_, code, 32, &insn);
        std::println("[0x{:016X}], {}", insn.runtime_address, insn.text);
    });
    uc_hook hook[2];
    uc_hook_add(emulator.uc_, &hook[0], UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, cb, &emulator, 0, 0xffffffffffffffff);

    const auto startTimePoint = std::chrono::system_clock::now();
    try {
        emulator.LoadSegments(DUMP_FILE_DIR);
        emulator.Run(0x000000000040C607);
        uint32_t t;
        CHECK_ERR(uc_mem_read(emulator.uc_, emulator.regs_.rsp_ + 0x49c, &t, 4));

        std::println("result = {}", t);
    } catch (std::exception &Exception) {
        std::println("Exception: {}", Exception.what());
    }

    std::println("Time elapsed: {}ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - startTimePoint).count());
}
