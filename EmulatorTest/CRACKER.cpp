#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE
#include <algorithm>
#include <chrono>
#include <print>
#include <ranges>
#include <thread>
#include <future>
#include <mutex>
#include <semaphore>
#include <queue>
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>

#include "../Utils/Emulator.h"
#include "../Utils/RapidMemoryDumper.h"
#include "../Utils/RapidRegisterStringParser.h"


#define PROCESS_ID          14656
#define DUMP_FILE_DIR       "../../EmulatorTest/DumpFile"
#define DUMP_BEGIN          0x0000000000400000
#define DUMP_END            0x0000000000720000
#define REGISTER_PARSER_STR R"(
RAX : 0000000000000018
RBX : 0000000000000040     '@'
RCX : 000000000065F0F0
RDX : 0000000056004C18
RBP : 0000000000000023     '#'
RSP : 000000000065F070     "(馜"
RSI : 0000000000732F20
RDI : 0000000000000000
R8  : 0000000003010200
R9  : 0000000000000000
R10 : 00000000000002A8     L'ʨ'
R11 : 000000000065EC30
R12 : 000000000073A4A0     "11223344556677889900112233445566"
R13 : 0000000000000023     '#'
R14 : 0000000000442D60     k.0000000000442D60
R15 : 000000000000002C     ','
RIP : 000000000040CE51     k.000000000040CE51
RFLAGS : 0000000000000204     L'Ȅ'
ZF : 0
OF : 0
CF : 0
PF : 1
SF : 0
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
DR6 : 00000000FFFF0FF0
DR7 : 0000000000BF0405

)"

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));


    RipperMemoryDumper rip(PROCESS_ID, DUMP_FILE_DIR);
    rip.DumpMemory(DUMP_BEGIN, DUMP_END);


    std::vector<SEG_MAP_MEM> mem;
    for (const std::filesystem::path directory(DUMP_FILE_DIR);
         const auto &                entry: std::filesystem::directory_iterator(directory)) {
        auto fileNamePath = entry.path().filename();
        auto fileNameStr  = fileNamePath.string();
        if (fileNamePath.extension() != ".bin" || !fileNameStr.starts_with("ba") || 2 + 16 != fileNameStr.find("si")) {
            continue;
        }

        const auto dumpBase = std::stoull(fileNameStr.substr(2, 16), nullptr, 16);
        const auto dumpSize = std::stoull(fileNameStr.substr(2 + 16 + 2, 16), nullptr, 16);

        auto buffer = ReadFileBinary(entry.path().string());
        mem.emplace_back(dumpBase, dumpSize, buffer);
    }

    const auto startTimePoint = std::chrono::system_clock::now();

    REGS parsedRegs = ParseRegisterString(REGISTER_PARSER_STR);
    for (uint8_t a = 0x00; a < 0xff; ++a) {
        std::println("current a = {:02X}", a);
        for (uint8_t b = 0x00; b < 0xff; ++b) {
            uint32_t    edx = 0x56004C00 + (a << 0x10) + (b << 0x0);
            X64Emulator emulator { parsedRegs, false };

            bool firstCall = true;
            emulator.RegisterObserver(0, [&firstCall, &edx](X64Emulator *Emu) {
                if (firstCall) {
                    Emu->regs_.rdx_ = edx;
                    firstCall       = false;
                    Emu->WriteRegs();
                }
            });

            try {
                emulator.LoadSegments({ mem.begin(), mem.end() });
                emulator.Run(0x000000000040CE56);

                uint32_t t;
                CHECK_ERR(uc_mem_read(emulator.uc_, emulator.regs_.rsp_ + 0x49c, &t, 4));

                if (t == 0) {
                    throw std::runtime_error(std::format("the edx=0x{:08X}", edx));
                }
            } catch (std::exception &Exception) {
                std::println("Exception: {}", Exception.what());
            }
        }
    }
    std::println("Time elapsed: {}ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - startTimePoint).count());
}
