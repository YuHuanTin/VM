#include <print>
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

void DoAnalyze(const X64Emulator *Emulator) {
    auto    currentRip = Emulator->regs_.rip_;
    uint8_t code[32];
    CHECK_ERR(uc_mem_read(Emulator->uc_, currentRip, code, 32));

    ZydisDisassembledInstruction insn;
    if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, currentRip, code, 32, &insn))) {
        throw std::runtime_error(std::format("Failed on ZyanDisassembleIntel with error returned: {}", currentRip));
    }

    auto isJcc = [](ZydisDisassembledInstruction &Insn) {
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
        std::println("[0x{:016X}]: {}", insn.runtime_address, insn.text);
    }
    std::println("{}", insn.text);
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
    emulator.RegisterObserver(0, DoAnalyze);
    emulator.Run();


    system("pause");
    return 0;
}
