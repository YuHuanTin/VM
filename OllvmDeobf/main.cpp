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
RAX : 00007FFF312CDF50
RBX : 0000000000000000
RCX : FFFFFFFFFFFFFFFF
RDX : 0000000E1F78F540
RBP : 0000000E10000000
RSP : 0000000E10000000
RSI : 00007FF74DEFDA16
RDI : 0000000E1F78F238
R8  : 0000000E1F78F568
R9  : 0000000000000020
R10 : 33751117CA1A41DC
R11 : 0000000E1F78F280
R12 : 0000000015814A67
R13 : 0000000000000004
R14 : 0000000000000000
R15 : 00007FF74D860000
RIP : 0000000000401E80
RFLAGS : 0000000000000206

)"

std::vector<std::pair<uint64_t, uint64_t> > true_block {
    { 4204176, 4204182 }, { 4203066, 4203066 }, { 4203071, 4203098 }, { 4203103, 4203157 }, { 4203162, 4203314 }, { 4203319, 4203341 }, { 4203346, 4203366 },
    { 4203371, 4203398 }, { 4203403, 4203428 }, { 4203433, 4203457 }, { 4203462, 4203490 }, { 4203495, 4203514 }, { 4203519, 4203558 }, { 4203563, 4203585 },
    { 4203590, 4203609 }, { 4203614, 4203636 }, { 4203641, 4203651 }, { 4203656, 4203689 }, { 4203694, 4203737 }, { 4203742, 4203776 }, { 4203781, 4203804 },
    { 4203809, 4203831 }, { 4203836, 4203856 }, { 4203861, 4203888 }, { 4203893, 4203918 }, { 4203923, 4203957 }, { 4203962, 4203981 }, { 4203986, 4204025 },
    { 4204030, 4204040 }, { 4204045, 4204067 }, { 4204072, 4204091 }, { 4204096, 4204118 }, { 4204123, 4204133 }, { 4204138, 4204171 }
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

    // 判断是否为 true_block 开头
    const auto it = std::ranges::find_if(true_block, [rip](const auto &v) {
        return v.second == rip;
    });
    if (it != true_block.end()) {
        trace_block.emplace_back(it->first, it->second, static_cast<uint8_t>((flag >> 6) & 1));
        true_block.erase(it);
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

    const auto str = ReadFileBinary("../../OllvmDeobf/test-fla");

    RapidMemoryLoader loader;
    loader.AppendMoreSegs(SEG_MAP_MEM { .base_ = 0x400000, .size_ = 0x100000, .buffer_ = str });

    uc_hook passUnMapped, passCall;

    try {
        // 注意 map 的栈地址是倒着的！所以应该是 -0x1000 的地址开始，到 0x0000000E10000000 结束
        uc_mem_map(x64_emulator.uc_, 0x0000000E10000000 - 0x1000, 0x1000, UC_PROT_ALL);

        uc_hook_add(x64_emulator.uc_, &passUnMapped, UC_HOOK_MEM_UNMAPPED | UC_HOOK_INTR, hook_mem_unmapped, nullptr, 1, 0);
        uc_hook_add(x64_emulator.uc_, &passCall, UC_HOOK_CODE, hook_call_inst, nullptr, 1, 0);

        x64_emulator.LoadSegments(loader.GetSegMap());
        x64_emulator.Run(0x0000000000402696, true);
    } catch (std::exception &Exception) {
        std::println("{}", Exception.what());
    }

    std::println("{}", true_block);
    // std::println("{}", trace_block);
    for (auto &[start,end,zf]: trace_block) {
        std::print("(({},{}),{}), ", start, end, zf);
    }
}
