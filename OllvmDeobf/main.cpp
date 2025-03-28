#include <Zydis/Zydis.h>
#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE

#include <cstdint>
#include <expected>
#include <fstream>
#include <print>
#include <span>
#include <string>
#include <vector>


#include "../Utils/Emulator.h"
#include "../Utils/RapidRegisterStringParser.h"
#include "../Utils/RapidMemoryLoader.h"


#define REGISTER_PARSER_STR R"(
RAX : 0000000000000000
RBX : 0000000000000000
RCX : 0000000000000000
RDX : 0000000000000000
RBP : 0000000000000000
RSP : 0000000E10000000
RSI : 0000000000000000
RDI : 0000000000000000
R8  : 0000000000000000
R9  : 0000000000000000
R10 : 0000000000000000
R11 : 0000000000000000
R12 : 0000000000000000
R13 : 0000000000000000
R14 : 0000000000000000
R15 : 0000000000000000
RIP : 00000000004023B0
RFLAGS : 0000000000000000

)"

std::vector<std::pair<uint64_t, uint64_t> > true_block {
    { 4205808, 4205814 }, { 4204590, 4204590 }, { 4204595, 4204622 }, { 4204627, 4204654 }, { 4204659, 4204679 }, { 4204684, 4204708 }, { 4204713, 4204763 }, { 4204768, 4204800 },
    { 4204805, 4204876 }, { 4204881, 4204918 }, { 4204923, 4204946 }, { 4204951, 4204961 }, { 4204966, 4204988 }, { 4204993, 4205013 }, { 4205018, 4205045 }, { 4205050, 4205075 },
    { 4205080, 4205104 }, { 4205109, 4205137 }, { 4205142, 4205161 }, { 4205166, 4205205 }, { 4205210, 4205232 }, { 4205237, 4205256 }, { 4205261, 4205283 }, { 4205288, 4205298 },
    { 4205303, 4205336 }, { 4205341, 4205362 }, { 4205367, 4205420 }, { 4205425, 4205435 }, { 4205440, 4205462 }, { 4205467, 4205487 }, { 4205492, 4205519 }, { 4205524, 4205549 },
    { 4205554, 4205576 }, { 4205581, 4205607 }, { 4205612, 4205631 }, { 4205636, 4205672 }, { 4205677, 4205699 }, { 4205704, 4205723 }, { 4205728, 4205750 }, { 4205755, 4205765 },
    { 4205770, 4205803 }
};

struct traceBlockInfo {
    uint64_t startAddr;
    uint64_t endAddr;
    uint8_t  zflag;
};

std::vector<traceBlockInfo> trace_block;

bool hook_mem_unmapped(
    uc_engine * uc,
    uc_mem_type type,
    uint64_t    address,
    int         size,
    int64_t     value,
    void *      user_data
) {
    uint64_t rip;
    CHECK_ERR(uc_reg_read(uc, UC_X86_REG_RIP, &rip))
    std::println("[!] unmapped 0x{:016X}", rip);
    return true;
}

bool hook_call_inst(
    uc_engine * uc,
    uc_mem_type type,
    uint64_t    address,
    int         size,
    int64_t     value,
    void *      user_data
) {
    // 获取当前的指令 ip
    size_t rip;
    CHECK_ERR(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    size_t flag;
    CHECK_ERR(uc_reg_read(uc, UC_X86_REG_RFLAGS, &flag));

    // 判断是否为 true_block 结尾
    const auto it = std::ranges::find_if(true_block, [rip](const auto &v) {
        return v.second == rip;
    });
    if (it != true_block.end()) {
        trace_block.emplace_back(it->first, it->second, static_cast<uint8_t>((flag >> 6) & 1));

        // 注意这里不能删除真实块，否则会少逻辑
        // true_block.erase(it);
    }

    uint8_t code[32];
    CHECK_ERR(uc_mem_read(uc, rip, code, 32));
    ZydisDisassembledInstruction insn;
    ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, rip, code, 32, &insn);

    // 跳过 call 调用，只需要获取当前函数的真实块派发顺序
    if (insn.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
        std::println("pass the call!");
        rip += insn.info.length;
        CHECK_ERR(uc_reg_write(uc, UC_X86_REG_RIP, &rip))
    }
    return true;
}

int main() {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    X64Emulator x64_emulator { ParseRegisterString(REGISTER_PARSER_STR) };

    const auto str = ReadFileBinary("../../OllvmDeobf/fla_num10");

    RapidMemoryLoader loader;
    loader.AppendMoreSegs(SEG_MAP_MEM { .base_ = 0x400000, .size_ = 0x100000, .buffer_ = str });

    uc_hook passUnMapped, passCall;

    try {
        // 注意 map 的栈地址是倒着的！所以应该是 -0x1000 的地址开始，到 0x0000000E10000000 结束
        uc_mem_map(x64_emulator.uc_, 0x0000000E10000000 - 0x1000, 0x1000, UC_PROT_ALL);

        uc_hook_add(x64_emulator.uc_, &passUnMapped, UC_HOOK_MEM_UNMAPPED | UC_HOOK_INTR, hook_mem_unmapped, nullptr, 1, 0);
        uc_hook_add(x64_emulator.uc_, &passCall, UC_HOOK_CODE, hook_call_inst, nullptr, 1, 0);

        x64_emulator.LoadSegments(loader.GetSegMap());
        x64_emulator.Run(0x0000000000402CF6, true);
    } catch (std::exception &Exception) {
        std::println("{}", Exception.what());
    }

    std::println("{}", true_block);
    // std::println("{}", trace_block);
    for (auto &[start,end,zf]: trace_block) {
        std::print("(({}, {}), {}), ", start, end, zf);
    }
}
