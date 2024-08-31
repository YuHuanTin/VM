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
#define DUMP_FILE_DIR       "../../V4/DumpFile"
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

struct RegisterWithAction {
    ZydisRegister       reg_;
    ZydisOperandActions actions_;
};

/**
 * 获取一条指令的所有寄存器和寄存器的操作（包括 mem 组合使用的寄存器）
 * @param Instruction 指令
 * @return RegisterWithOperands vec
 */
std::vector<RegisterWithAction> GetInstructionRegisterWithAction(const ZydisDisassembledInstruction &Instruction) {
    std::vector<RegisterWithAction> registers;
    for (int i = 0; i < Instruction.info.operand_count; ++i) {
        if (Instruction.operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            registers.emplace_back(Instruction.operands[i].reg.value, Instruction.operands[i].actions);
        } else if (Instruction.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            // todo, xor [esp], eax 这种情况可能有问题，但是不知道怎么解决
            if (Instruction.operands[i].mem.base != ZYDIS_REGISTER_NONE) {
                if (auto it = std::ranges::find_if(registers, [&Instruction, &i](auto &&RegisterWithAction) {
                        return RegisterWithAction.reg_ == Instruction.operands[i].mem.base;
                    });
                    it == registers.end()) {
                    registers.emplace_back(Instruction.operands[i].mem.base, ZYDIS_OPERAND_ACTION_READ);
                } else {
                    it->actions_ |= ZYDIS_OPERAND_ACTION_READ;
                }
            }
            if (Instruction.operands[i].mem.index != ZYDIS_REGISTER_NONE) {
                if (auto it = std::ranges::find_if(registers, [&Instruction, &i](auto &&RegisterWithAction) {
                        return RegisterWithAction.reg_ == Instruction.operands[i].mem.index;
                    });
                    it == registers.end()) {
                    registers.emplace_back(Instruction.operands[i].mem.index, ZYDIS_OPERAND_ACTION_READ);
                } else {
                    it->actions_ |= ZYDIS_OPERAND_ACTION_READ;
                }
            }
        }
    }
    return registers;
}

/**
 * 获取所有只有写操作的 RegisterWithAction
 * @param RegisterWithActions 所有 RegisterWithAction 
 * @return 筛选出只有写操作的 RegisterWithAction
 */
std::vector<RegisterWithAction> GetWriteOnlyRegisterWithAction(const std::vector<RegisterWithAction> &RegisterWithActions) {
    std::map<REGISTER_ORDER::RegisterType, std::vector<RegisterWithAction> > table;

    // 这里要处理类似于 mov eax, al 的情况，虽然是两个寄存器，但是是同一种类型的寄存器
    for (const auto [reg_, actions_]: RegisterWithActions) {
        table[REGISTER_ORDER::RegToType.at(reg_)].emplace_back(reg_, actions_);
    }

    std::vector<RegisterWithAction> result;
    for (const auto &[type, registers]: table) {
        if (std::ranges::any_of(registers, [](auto &reg_with_action) {
            return reg_with_action.actions_ & ZYDIS_OPERAND_ACTION_MASK_READ;
        })) {
            continue;
        }
        result.insert_range(result.end(), registers);
    }

    return result;
}

/**
 * 向上搜索含有目标同类寄存器的指令，如果为 '读写' 则将其替换为 '读', 如果为 '读' 则返回, 如果为 '写' 则移除 '写' 并继续向上搜索
 * @param Index 当前指令索引
 * @param Register 目标寄存器
 */
void BackSearch(int Index, const ZydisRegister Register) {
    for (int i = Index - 1; i >= 0; --i) {
        std::map<REGISTER_ORDER::RegisterType, std::vector<RegisterWithAction> > table;
        for (auto [reg, action]: GetInstructionRegisterWithAction(GlobalInstructions.at(i))) {
            table[REGISTER_ORDER::RegToType.at(reg)].emplace_back(reg, action);
        }
        // 没有同类寄存器则往前找
        if (!table.contains(REGISTER_ORDER::RegToType.at(Register))) {
            continue;
        }

        auto sameTypeRegisters = table.at(REGISTER_ORDER::RegToType.at(Register));
        auto it                = std::ranges::find_if(sameTypeRegisters, [](auto &reg_with_action) {
            return (reg_with_action.actions_ & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
        });
        if (it == sameTypeRegisters.end()) {
            break;
        }
        // 针对 mov rax, 1
        //     mov al, 2
        //     mov cl, ah
        // 这种情况，这种情况下，我们并不能直接消除第一个 mov
        if (it->reg_ > Register) {
            continue;
        }

        for (int j = 0; j < GlobalInstructions.at(i).info.operand_count; ++j) {
            if (GlobalInstructions.at(i).operands[j].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                // todo has bug?
                // 针对这种情况 xchg al, ah 或者 xchg al, al，也许不能简单的删除两个寄存器的 w 属性
                if (GlobalInstructions.at(i).operands[j].reg.value == it->reg_ && GlobalInstructions.at(i).operands[j].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                    GlobalInstructions.at(i).operands[j].actions &= ~ZYDIS_OPERAND_ACTION_MASK_WRITE;
                    std::println("from\t[{}]{}\n"
                        "remove 'w' [{}]{}", Index, GetInstructionDetailsString(GlobalInstructions.at(Index)), i, GetInstructionDetailsString(GlobalInstructions.at(i)));
                    break;
                }
            }
        }

        // 再次读一遍该条指令，如果只剩下了 read 直接返回
        ++i;
    }
}

/**
 * 清理无用的指令
 */
void CleanJunkCode() {
    for (;;) {
        for (int i = 0; i < GlobalInstructions.size(); ++i) {
            std::println("{}, {}:{}", __func__, i, GetInstructionDetailsString(GlobalInstructions.at(i)));
            auto regsWithAction = GetInstructionRegisterWithAction(GlobalInstructions.at(i));
            auto writeOnlyRegs  = GetWriteOnlyRegisterWithAction(regsWithAction);
            if (writeOnlyRegs.empty()) {
                continue;
            }

            for (const auto &[reg_, actions_]: writeOnlyRegs) {
                BackSearch(i, reg_);
            }
        }

        bool hasChange = false;
        for (int i = 0, incOnlyPos = 0; i < GlobalInstructions.size(); ++i, ++incOnlyPos) {
            auto regsWithAction = GetInstructionRegisterWithAction(GlobalInstructions.at(i));
            if (regsWithAction.size() == 1 && regsWithAction.at(0).reg_ == ZYDIS_REGISTER_RIP) {
                std::println("{} remove[{}]: {}", __func__, incOnlyPos, GetInstructionDetailsString(GlobalInstructions.at(i)));
                GlobalInstructions.erase(GlobalInstructions.begin() + i);
                GlobalInstructionBytes.erase(GlobalInstructionBytes.begin() + i);
                --i;
                hasChange = true;
                continue;
            }
            if (std::ranges::all_of(regsWithAction, [](auto &reg_with_action) {
                return (reg_with_action.actions_ & ZYDIS_OPERAND_ACTION_MASK_WRITE) == 0;
            })) {
                std::println("{} remove[{}]: {}", __func__, incOnlyPos, GetInstructionDetailsString(GlobalInstructions.at(i)));
                GlobalInstructions.erase(GlobalInstructions.begin() + i);
                GlobalInstructionBytes.erase(GlobalInstructionBytes.begin() + i);
                --i;
                hasChange = true;
            }
        }

        if (!hasChange) {
            break;
        }
    }
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

    // 判断是否为 语句块结尾
    auto isJcc = [](const ZydisDisassembledInstruction &Insn) {
        const auto total   = Insn.info.operand_count;
        const auto visible = Insn.info.operand_count_visible;
        for (int i = visible; i < total; i++) {
            if (Insn.operands[i].reg.value == ZYDIS_REGISTER_RFLAGS) {
                return true;
            }
        }
        return false;
    };
    if (insn.info.mnemonic == ZYDIS_MNEMONIC_CALL
        || insn.info.mnemonic == ZYDIS_MNEMONIC_RET
        || insn.info.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE
        || insn.text[0] == 'j' && isJcc(insn)
    ) {
        std::println("end block signature at [0x{:016X}]: {}", insn.runtime_address, insn.text);
        CleanJunkCode();

        for (auto &GlobalInstruction: GlobalInstructions) {
            std::println("{}", GetInstructionDetailsString(GlobalInstruction));
        }
        for (auto &GlobalInstructionByte: GlobalInstructionBytes) {
            for (int j = 0; j < GlobalInstructionByte.size(); ++j) {
                std::print("{:02X} ", GlobalInstructionByte.at(j));
            }
        }
        std::println("");

        GlobalInstructions.clear();
        GlobalInstructionBytes.clear();
    }
}

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));


    REGISTER_ORDER::InitializeMaps();

    RipperMemoryDumper rip(PROCESS_ID, DUMP_FILE_DIR);
    rip.DumpMemory(DUMP_BEGIN, DUMP_END);
    RapidMemoryLoader<SEG_MAP_MEM_X86> loader(DUMP_FILE_DIR);
    loader.AppendMoreSegs<SEG_MAP_X86>({ 0x0019D000, 0x00003000, "D:/我的文件/IDM/下载文件-IDM/destination - 副本_0019D000.bin" });

    const REGS_X86 parsedRegs = ParseRegisterString_X86(REGISTER_PARSER_STR);
    X86Emulator    emulator { parsedRegs };

    emulator.RegisterObserver(0, DoAnalyze);
    try {
        emulator.LoadSegments(loader.GetSegMap());
        emulator.Run();
    } catch (std::exception &Exception) {
        std::println("Exception: {}", Exception.what());
    }
}