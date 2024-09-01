#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE
#include <algorithm>
#include <chrono>
#include <map>
#include <print>
#include <ranges>
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>

#include "../Utils/Emulator.h"
#include "../Utils/RapidMemoryDumper.h"
#include "../Utils/RapidMemoryLoader.h"
#include "../Utils/RapidRegisterStringParser.h"


#define PROCESS_ID          10568
#define DUMP_FILE_DIR       "../../EmulatorTest/DumpFile"
#define DUMP_BEGIN          0x00400000
#define DUMP_END            0x00430000
#define REGISTER_PARSER_STR R"(
EAX : 00000000
EBX : 00000000
ECX : 004140D7     destination - 副本.004140D7
EDX : 770C9050     ntdll.770C9050
EBP : 0019F7B0
ESP : 0019F790     &"虌%"
ESI : 00000000
EDI : 00000000
EIP : 004140D7     destination - 副本.004140D7
EFLAGS : 00000244     L'Ʉ'
ZF : 1
OF : 0     L'̀'
CF : 0
PF : 1
SF : 0
TF : 0     L'Ā'
AF : 0     L'Ā'
DF : 0
IF : 1
LastError : 00000000 (ERROR_SUCCESS)
LastStatus : C0000139 (STATUS_ENTRYPOINT_NOT_FOUND)
GS : 002B
ES : 002B
CS : 0023
FS : 0053
DS : 002B
SS : 002B     '+'
DR0 : 00000000
DR1 : 00000000
DR2 : 00000000
DR3 : 00000000
DR6 : 00000000
DR7 : 00000000

)"


std::vector<ZydisDisassembledInstruction> GlobalInstructions;
std::vector<std::vector<uint8_t> >        GlobalInstructionBytes;

struct InstructionWithData {
    ZydisDisassembledInstruction Instruction;
    std::vector<uint8_t>         Bytes;
};

std::map<uint64_t, std::vector<InstructionWithData> > GlobalInstructionBranch;

std::string GetRegisterNameByEnum(const ZydisRegister Index) {
    auto registerName = std::string { NAMEOF_ENUM(Index) };
    std::ranges::for_each(registerName, [](char &r) { r = tolower(r); });
    registerName = registerName.substr(registerName.find_last_of('_') + 1);
    return registerName;
}

std::string GetInstructionDetailsString(ZydisDisassembledInstruction &Instruction) {
    std::string detailInfo;

    auto formatOutput = [](const ZydisRegister Register, const ZydisOperandActions Actions) {
        auto registerName = GetRegisterNameByEnum(Register);

        if (Actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_MASK_READ && Actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_MASK_WRITE) {
            // 默认先读后写？
            return std::format("{:<6s}: rw, ", registerName);
        } else if (Actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_MASK_WRITE) {
            return std::format("{:<6s}: w , ", registerName);
        } else if (Actions & ZYDIS_OPERAND_ACTION_MASK_READ) {
            return std::format("{:<6s}: r , ", registerName);
        } else {
            return std::string {};
        }
    };

    for (int j = 0; j < Instruction.info.operand_count; ++j) {
        if (Instruction.operands[j].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            detailInfo += formatOutput(Instruction.operands[j].reg.value, Instruction.operands[j].actions);
        }
    }
    return std::format("[0x{:016X}]: {:<32s}, {}", Instruction.runtime_address, Instruction.text, detailInfo);
}

auto IsJcc(const ZydisDisassembledInstruction &Insn) {
    if (Insn.text[0] != 'j') {
        return false;
    }
    const auto total = Insn.info.operand_count;
    for (int i = 0; i < total; i++) {
        if (Insn.operands[i].reg.value == ZYDIS_REGISTER_EFLAGS) {
            return true;
        }
    }
    return false;
}

/**
 * 函数流程图分析
 */
void BranchAnalyze() {
    bool                  hasMultiBranch = false;
    uint64_t              begin          = GlobalInstructions.at(0).runtime_address;
    std::vector<uint64_t> okAddr;
    for (int i = 0; i < GlobalInstructions.size(); i++) {
        auto &GlobalInstruction     = GlobalInstructions.at(i);
        auto &GlobalInstructionByte = GlobalInstructionBytes.at(i);

        if (hasMultiBranch) {
            begin          = GlobalInstruction.runtime_address;
            hasMultiBranch = false;
        }
        if (!IsJcc(GlobalInstruction)) {
            if (!std::ranges::contains(okAddr, begin)) {
                GlobalInstructionBranch[begin].emplace_back(GlobalInstruction, GlobalInstructionByte);
            }
            continue;
        }

        // assume jz, then have two branches, emulator will choose one of and run, so we just pass to next instruction and log address as new branch
        if (!std::ranges::contains(okAddr, begin)) {
            GlobalInstructionBranch[begin].emplace_back(GlobalInstruction, GlobalInstructionByte);
        }
        hasMultiBranch = true;
        okAddr.emplace_back(begin);
    }

    for (auto &[k, v]: GlobalInstructionBranch) {
        std::println("branch address: 0x{:016X}", k);
        int i = 0;
        for (i = 0; i < v.size(); i++) {
            std::println("{}", GetInstructionDetailsString(v.at(i).Instruction));
        }    
        for (i = 0; i < v.size(); i++) {
            for (int j = 0; j < v.at(i).Bytes.size(); j++) {
                std::print("{:02X} ", v.at(i).Bytes.at(j));
            }
        }
        std::println("");

        i--;

        if (IsJcc(v.at(i).Instruction)) {
            std::println("branch 1 -> {:016X}", v.at(i).Instruction.runtime_address + v.at(i).Instruction.info.length + v.at(i).Instruction.operands[0].imm.value.u);
            std::println("branch 2 -> {:016X}", v.at(i).Instruction.runtime_address + v.at(i).Instruction.info.length);
        }
    }
    // for (auto &[k, v]: GlobalInstructionBranch) {
    //     for (int i = 0; i < v.size(); i++) {
    //         for (int j = 0; j < v.at(i).Bytes.size(); j++) {
    //             std::print("{:02X} ", v.at(i).Bytes.at(j));
    //         }
    //     }
    //     std::println("");
    // }
}

void DoAnalyze(const X86Emulator *Emulator) {
    auto    currentRip = Emulator->regs_.eip_;
    uint8_t code[32];
    CHECK_ERR(uc_mem_read(Emulator->uc_, currentRip, code, 32));

    ZydisDisassembledInstruction insn;
    if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, currentRip, code, 32, &insn))) {
        throw std::runtime_error(std::format("Failed on ZyanDisassembleIntel with error returned: {}", currentRip));
    }

    // 加入指令
    GlobalInstructions.emplace_back(insn);
    GlobalInstructionBytes.emplace_back(code, code + insn.info.length);

    if (insn.info.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        GlobalInstructions.pop_back();
        GlobalInstructionBytes.pop_back();
        return;
    }
    while (insn.info.mnemonic == ZYDIS_MNEMONIC_RET) {
        int size      = GlobalInstructions.size();
        int indexCall = size - 2 - 1; // call xxxx
        if (indexCall < 0) {
            break;
        }

        if (GlobalInstructions.at(indexCall).info.mnemonic != ZYDIS_MNEMONIC_CALL) {
            break;
        }
        if (GlobalInstructions.at(indexCall).operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            break;
        }
        if (GlobalInstructions.at(indexCall).operands[0].imm.value.u + GlobalInstructions.at(indexCall).runtime_address + GlobalInstructions.at(indexCall).info.length
            != GlobalInstructions.at(indexCall + 1).runtime_address) {
            break;
        }

        for (int i = 0; i < 3; ++i) {
            GlobalInstructions.pop_back();
            GlobalInstructionBytes.pop_back();
        }
        return;
    }
    while (insn.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {
        int size    = GlobalInstructions.size();
        int indexJz = size - 2; // call xxxx
        if (indexJz < 0) {
            break;
        }

        if (GlobalInstructions.at(indexJz).info.mnemonic != ZYDIS_MNEMONIC_JZ) {
            break;
        }

        if (GlobalInstructions.at(indexJz).operands[0].imm.value.u - GlobalInstructions.at(indexJz).info.length
            != GlobalInstructions.at(indexJz + 1).operands[0].imm.value.u) {
            break;
        }

        for (int i = 0; i < 2; ++i) {
            GlobalInstructions.pop_back();
            GlobalInstructionBytes.pop_back();
        }
        return;
    }
}

void cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    if (type == UC_MEM_WRITE) {
        std::println("[Write] address: 0x{:016X}, value: 0x{:016X}, size: {}", address, value, size);
    }
    if (type == UC_MEM_READ) {
        uint64_t v = 0;
        CHECK_ERR(uc_mem_read(uc, address, &v, size));
        std::println("[Read]  address: 0x{:016X}, size: {}, value: 0x{:016X}", address, size, v);
    }
    if (type == UC_MEM_FETCH) {
        throw std::runtime_error("Failed on UC_MEM_FETCH");
    }
}

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));


    REGISTER_ORDER::InitializeMaps();

    // RipperMemoryDumper rip(PROCESS_ID, DUMP_FILE_DIR);
    // rip.DumpMemory(DUMP_BEGIN, DUMP_END);
    RapidMemoryLoader<SEG_MAP_MEM_X86> loader(DUMP_FILE_DIR);
    loader.AppendMoreSegs<SEG_MAP_X86>({ 0x0019D000, 0x00003000, "destination - 副本_0019D000.bin" });

    const REGS_X86 parsedRegs = ParseRegisterString_X86(REGISTER_PARSER_STR);
    X86Emulator    emulator { parsedRegs };

    emulator.RegisterObserver(0, DoAnalyze);
    // uc_hook hook;
    // uc_hook_add(emulator.uc_, &hook, UC_HOOK_MEM_VALID, cb, &emulator, 0x0019D000, 0x00424000);


    try {
        emulator.LoadSegments(loader.GetSegMap());
        emulator.Run(0x00414504);


        std::println("-------------------------------------end -------------------------------------");
        BranchAnalyze();
    } catch (std::exception &Exception) {
        std::println("Exception: {}", Exception.what());
    }
}
