//
// Created by AFETT on 2024/8/21.
//

#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE
#define CLEANUP_DETAILS 0
#include <algorithm>
#include <print>
#include <ranges>
#include <span>
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>

#include "../Utils/Emulator.h"

#define INIT_RAX 			0x0000000000000001
#define INIT_RBX			0x0000000000000000
#define INIT_RCX			0x0000000000000001
#define INIT_RDX			0x000001453D945F80
#define INIT_RBP			0x0000000000000000
#define INIT_RSP			0x00000024C1DFFA18
#define INIT_RSI			0x0000000000000000
#define INIT_RDI			0x0000000000000000
#define INIT_R8 			0x000001453D94AD00
#define INIT_R9 			0x00000024C1DFF918
#define INIT_R10			0x0000000000000012
#define INIT_R11			0x00000024C1DFF9C0
#define INIT_R12			0x0000000000000000
#define INIT_R13			0x0000000000000000
#define INIT_R14			0x0000000000000000
#define INIT_R15			0x0000000000000000
#define INIT_RIP			0x00007FF7507BA4A5
#define INIT_RFL			0x0000000000000204      // WARNING: NEVER SET 'TF' = 1

SEG_MAP segs[] = {
    //base			size			file name
    { 0x00007FF7506B5000, 0x0000000000003000, "../../Utils/v1_testexec.vmp_00007FF7506B5000.bin" },
    { 0x00007FF7506B8000, 0x0000000000001000, "../../Utils/v1_testexec.vmp_00007FF7506B8000.bin" },
    { 0x00007FF7506B9000, 0x0000000000001000, "../../Utils/v1_testexec.vmp_00007FF7506B9000.bin" },
    { 0x00007FF7506BA000, 0x0000000000101000, "../../Utils/v1_testexec.vmp_00007FF7506BA000.bin" },
    { 0x00000024C1DFA000, 0x0000000000006000, "../../Utils/v1_testexec.vmp_00000024C1DFA000.bin" },
};

std::vector<ZydisDisassembledInstruction> GlobalInstructions;
constexpr int                             RegisterMaxValue = ZydisRegister::ZYDIS_REGISTER_MAX_VALUE;

std::string GetRegisterNameByEnum(const ZydisRegister Index) {
    auto registerName = std::string { NAMEOF_ENUM(Index) };
    std::ranges::for_each(registerName, [](char &r) { r = tolower(r); });
    registerName = registerName.substr(registerName.find_last_of('_') + 1);
    return registerName;
}

std::string_view GetOperandNameByEnum(const ZydisOperandAction Index) {
    return NAMEOF_ENUM(Index);
}

void GetInstructionDetails(ZydisDisassembledInstruction &Instruction) {
    std::string str;

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
            str += formatOutput(Instruction.operands[j].reg.value, Instruction.operands[j].actions);
        }
    }

    std::println("{:<32s}, {}", Instruction.text, str);
}

std::string GetInstructionDetailsString(ZydisDisassembledInstruction &Instruction) {
    std::string str;

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
            str += formatOutput(Instruction.operands[j].reg.value, Instruction.operands[j].actions);
        }
    }

    return std::format("{:<32s}, {}", Instruction.text, str);
}

auto GenMatrixFromInstruction(auto &&Instructions) {
    //                          instruction register action1
    //              register1 {     ...
    //                          instruction register action2
    // matrix:      
    //                          instruction register action1
    //              register2 {     ...
    //                          instruction register action2
    std::array<std::vector<uint8_t>, RegisterMaxValue> matrix;
    // init
    for (int i = 0; i < Instructions.size(); ++i) {
        for (int j = 0; j < RegisterMaxValue; ++j) {
            matrix.at(j).emplace_back(0);
        }

        auto &ins = Instructions.at(i);
        for (int j = 0; j < ins.info.operand_count; ++j) {
            if (ins.operands[j].type == ZYDIS_OPERAND_TYPE_REGISTER)
                matrix.at(ins.operands[j].reg.value).at(i) = ins.operands[j].actions;
        }
    }
    return matrix;
};

void CleanJunkCode() {
    for (;;) {
        int  removableInstructionCount = 0;
        auto matrix                    = GenMatrixFromInstruction(GlobalInstructions);

        // 遍历所有寄存器
        for (int registerIndex = 0; registerIndex < RegisterMaxValue; ++registerIndex) {
            auto &registerActions = matrix.at(registerIndex);

            // 遍历所有寄存器的指令 action
            for (int registerActionIndex = 0; registerActionIndex < registerActions.size(); ++registerActionIndex) {
                auto removePrevRegisterAction = [&registerIndex, &registerActions](const int currentActionIndex) {
                    int removableCount = 0;
                    for (int i = currentActionIndex - 1; i >= 0; --i) {
                        if (registerActions.at(i) & ZYDIS_OPERAND_ACTION_MASK_READ && registerActions.at(i) & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                            auto actionBefore = registerActions.at(i);
                            registerActions.at(i) &= ~ZYDIS_OPERAND_ACTION_MASK_WRITE;
#if CLEANUP_DETAILS == 1
                            std::println("rw,register[{}]\n"
                                "operator [{}]->[{}]\n"
                                "instr [{}]\n"
                                "from  [{}]",
                                GetRegisterNameByEnum(static_cast<ZydisRegister>(registerIndex)),
                                GetOperandNameByEnum(static_cast<ZydisOperandAction>(actionBefore)), GetOperandNameByEnum(static_cast<ZydisOperandAction>(registerActions.at(i))),
                                GetInstructionDetailsString(GlobalInstructions.at(i)),
                                GetInstructionDetailsString(GlobalInstructions.at(currentActionIndex)));
#endif
                            ++removableCount;
                            break;
                        } else if (registerActions.at(i) & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                            auto actionBefore = registerActions.at(i);
                            registerActions.at(i) &= ~ZYDIS_OPERAND_ACTION_MASK_WRITE;
#if CLEANUP_DETAILS == 1
                            std::println(" w,register[{}]\n"
                                "operator [{}]->[{}]\n"
                                "instr [{}]\n"
                                "from  [{}]",
                                GetRegisterNameByEnum(static_cast<ZydisRegister>(registerIndex)),
                                GetOperandNameByEnum(static_cast<ZydisOperandAction>(actionBefore)), GetOperandNameByEnum(static_cast<ZydisOperandAction>(registerActions.at(i))),
                                GetInstructionDetailsString(GlobalInstructions.at(i)),
                                GetInstructionDetailsString(GlobalInstructions.at(currentActionIndex)));
#endif
                            ++removableCount;
                        } else if (registerActions.at(i) & ZYDIS_OPERAND_ACTION_MASK_READ) {
                            break;
                        }
                    }
                    return removableCount;
                };

                const auto &registerAction = registerActions.at(registerActionIndex);
                if (registerAction & ZYDIS_OPERAND_ACTION_MASK_READ && registerAction & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                    // default 'read' before 'write'
                    // do nothing
                } else if (registerAction & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                    // todo maybe error?
                    /* removableInstructionCount += */
                    removePrevRegisterAction(registerActionIndex);
                } else if (registerAction & ZYDIS_OPERAND_ACTION_MASK_READ) {
                    // do nothing
                } else {
                    // do nothing
                }
            }
        }

        // 删除所有都是 r 的情况的指令（按照原则1）
        for (int instructionIndex = 0, deleteIndex = 0; instructionIndex < matrix.at(0).size(); instructionIndex++, deleteIndex++) {
            // todo verify that
            // ignore only change IP, FLAGS?
            bool remove = true;
            for (int registerIndex = 0; registerIndex <= ZydisRegister::ZYDIS_REGISTER_R15; registerIndex++) {
                if (matrix.at(registerIndex).at(instructionIndex) & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                    remove = false;
                    break;
                }
            }

            if (remove) {
#if CLEANUP_DETAILS == 1
                std::println("remove instruction at [{}], instruction is: {}", instructionIndex, GlobalInstructions.at(deleteIndex).text);
#endif

                GlobalInstructions.erase(GlobalInstructions.begin() + deleteIndex--);

                // todo
                ++removableInstructionCount;
            }
        }

        if (removableInstructionCount == 0)
            break;
    }

#if CLEANUP_DETAILS == 1
    std::println("the cleanup code:");
#endif
    for (auto &GlobalInstruction: GlobalInstructions) {
        GetInstructionDetails(GlobalInstruction);
    }
    GlobalInstructions.clear();
}

void doAnalyze(const X64Emulator *Emulator) {
    auto    currentRip = Emulator->regs_.rip_;
    uint8_t code[32];
    CHECK_ERR(uc_mem_read(Emulator->uc_, currentRip, code, 32));

    ZydisDisassembledInstruction insn;
    if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, currentRip, code, 32, &insn))) {
        throw std::runtime_error(std::format("Failed on ZyanDisassembleIntel with error returned: {}", currentRip));
    }

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
        CleanJunkCode();
        std::println("[0x{:016X}]: {}", insn.runtime_address, insn.text);
    }

    GlobalInstructions.push_back(insn);
}

int main(int argc, char **argv, char **envp) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));

    X64Emulator emulator {
        {
            .rax_ = INIT_RAX, .rbx_ = INIT_RBX, .rcx_ = INIT_RCX, .rdx_ = INIT_RDX,
            .rbp_ = INIT_RBP, .rsp_ = INIT_RSP, .rsi_ = INIT_RSI, .rdi_ = INIT_RDI,
            .r8_ = INIT_R8, .r9_ = INIT_R9, .r10_ = INIT_R10, .r11_ = INIT_R11,
            .r12_ = INIT_R12, .r13_ = INIT_R13, .r14_ = INIT_R14, .r15_ = INIT_R15,
            .rip_ = INIT_RIP, .rflags_ = INIT_RFL
        }
    };
    emulator.LoadSegments(segs);
    emulator.WriteRegs();
    emulator.RegisterObserver(0, doAnalyze);
    emulator.Run();


    system("pause");
    return 0;
}
