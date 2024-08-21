//
// Created by AFETT on 2024/8/21.
//


#include <fstream>
#include <print>
#include <span>
#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>

#include "def.h"

#if ARCHITECTURE == ARCHITECTURE_X64
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
#elif ARCHITECTURE == ARCHITECTURE_X86
#define INIT_EAX			0x00000001
#define INIT_EBX			0x00000000
#define INIT_ECX			0x75105AA0
#define INIT_EDX			0x751545D0
#define INIT_EBP			0x0019FF70
#define INIT_ESP			0x0019FF20
#define INIT_ESI			0x75105584
#define INIT_EDI			0x75105AD4
#define INIT_EIP			0x00424596
#define INIT_EFL			0x00000206
#endif

SEG_MAP segs[] = {
    //base			size			file name
    { 0x00007FF7506B5000, 0x0000000000003000, "v1_testexec.vmp_00007FF7506B5000.bin" },
    { 0x00007FF7506B8000, 0x0000000000001000, "v1_testexec.vmp_00007FF7506B8000.bin" },
    { 0x00007FF7506B9000, 0x0000000000001000, "v1_testexec.vmp_00007FF7506B9000.bin" },
    { 0x00007FF7506BA000, 0x0000000000101000, "v1_testexec.vmp_00007FF7506BA000.bin" },
    { 0x00000024C1DFA000, 0x0000000000006000, "v1_testexec.vmp_00000024C1DFA000.bin" },
};


std::string ReadFileBinary(std::string_view FileName) {
    std::fstream fs { FileName.data(), std::ios::in | std::ios::binary };
    fs.seekg(0, std::ios::end);
    const auto length = fs.tellg();
    fs.seekg(0, std::ios::beg);

    std::string buf(length, '\0');
    fs.read(&buf[0], length);
    return buf;
}

class X64Emulator {
public:
    uc_engine *uc_ { nullptr };
    REGS       regs_ {
        .rax_ = INIT_RAX, .rbx_ = INIT_RBX, .rcx_ = INIT_RCX, .rdx_ = INIT_RDX,
        .rbp_ = INIT_RBP, .rsp_ = INIT_RSP, .rsi_ = INIT_RSI, .rdi_ = INIT_RDI,
        .r8_ = INIT_R8, .r9_ = INIT_R9, .r10_ = INIT_R10, .r11_ = INIT_R11,
        .r12_ = INIT_R12, .r13_ = INIT_R13, .r14_ = INIT_R14, .r15_ = INIT_R15,
        .rip_ = INIT_RIP, .rflags_ = INIT_RFL
    };
    int reg_batch_[18] = {
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_RFLAGS
    };
    void *reg_value_batch_[18] = {
        &regs_.rax_, &regs_.rbx_, &regs_.rcx_, &regs_.rdx_,
        &regs_.rbp_, &regs_.rsp_, &regs_.rsi_, &regs_.rdi_,
        &regs_.r8_, &regs_.r9_, &regs_.r10_, &regs_.r11_,
        &regs_.r12_, &regs_.r13_, &regs_.r14_, &regs_.r15_,
        &regs_.rip_, &regs_.rflags_
    };

    X64Emulator() {
        std::println("Emulate AMD64 machine code");
        CHECK_ERR(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_));
    }

    void LoadSegments(std::span<SEG_MAP> Segs) {
        // map memory for this emulation
        for (auto [base_, size_, file_name_]: Segs) {
            auto buffer = ReadFileBinary(file_name_);
            assert(buffer.size() == size_ && "Segment size mismatch?");

            // map memory for this emulation
            CHECK_ERR(uc_mem_map(uc_, base_, size_, UC_PROT_ALL));

            // write machine code to be emulated to memory
            CHECK_ERR(uc_mem_write(uc_, base_, buffer.data(), size_));

            std::println("Segment [0x{:x}, 0x{:x}] loaded from file: {}", base_, base_ + size_, file_name_);
        }
    }

    void WriteRegs() {
        CHECK_ERR(uc_reg_write_batch(uc_, reg_batch_, reg_value_batch_, std::size(reg_value_batch_)));
    }

    void ReadRegs() {
        CHECK_ERR(uc_reg_read_batch(uc_, reg_batch_, reg_value_batch_, std::size(reg_value_batch_)));
    }

    void PrintRegs() {
        std::println(
            "rax = 0x{:016X}\nrbx = 0x{:016X}\nrcx = 0x{:016X}\nrdx = 0x{:016X}\n"
            "rbp = 0x{:016X}\nrsp = 0x{:016X}\nrsi = 0x{:016X}\nrdi = 0x{:016X}\n"
            "r8 =  0x{:016X}\nr9 =  0x{:016X}\nr10 = 0x{:016X}\nr11 = 0x{:016X}\n"
            "r12 = 0x{:016X}\nr13 = 0x{:016X}\nr14 = 0x{:016X}\nr15 = 0x{:016X}\n"
            "rip = 0x{:016X}\nrflag=0x{:016X}\n",
            regs_.rax_, regs_.rbx_, regs_.rcx_, regs_.rdx_,
            regs_.rbp_, regs_.rsp_, regs_.rsi_, regs_.rdi_,
            regs_.r8_, regs_.r9_, regs_.r10_, regs_.r11_,
            regs_.r12_, regs_.r13_, regs_.r14_, regs_.r15_,
            regs_.rip_, regs_.rflags_);
    }

    void PrintStack(uint64_t Rsp) {
        uint64_t val;
        for (int i = 0; i < 10; i++) {
            uc_mem_read(uc_, Rsp, &val, 8);
            std::println("|0x{:016X}|", val);
            Rsp += 8;
        }
    }

    void Run() {
        uint8_t code[32];
        int     count = 0;
        for (;;) {
            count++;
            CHECK_ERR(uc_mem_read(uc_, regs_.rip_, code, 32));

            ZydisDisassembledInstruction insn;
            ZydisDisassembleIntel(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, regs_.rip_, code, 32, &insn);

            std::println("{}", insn.text);


            switch (regs_.rip_) {
                case 0x00007FF750717456: {
                    // scanf
                    PrintRegs();

                    // read rcx, rdx ( 2 params for x64 call)
                    char str[3];
                    CHECK_ERR(uc_mem_read(uc_, regs_.rcx_, str, 3));
                    std::println("scanf format = {}", str);

                    // write rdx ( emulation scanf input )
                    CHECK_ERR(uc_mem_write(uc_, regs_.rdx_, "123", 3));

                    regs_.rip_ = 0x00007FF7507BA4B1;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RIP, &regs_.rip_));

                    regs_.rsp_ += 8 * 2;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RSP, &regs_.rsp_));

                    PrintRegs();
                    PrintStack(regs_.rsp_);
                    std::println("call scanf!");
                    break;
                }
                case 0x00007FF7506BD4B6: {
                    // strcmp
                    PrintRegs();

                    char rcx_value[20];
                    CHECK_ERR(uc_mem_read(uc_, regs_.rcx_, rcx_value, 20));
                    char rdx_value[20];
                    CHECK_ERR(uc_mem_read(uc_, regs_.rdx_, rdx_value, 20));

                    regs_.rax_ = 1; // always fail!
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RAX, &regs_.rax_));

                    regs_.rip_ = 0x00007FF7507BA4BC;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RIP, &regs_.rip_));

                    regs_.rsp_ += 8 * 2;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RSP, &regs_.rsp_));

                    PrintRegs();
                    PrintStack(regs_.rsp_);
                    std::println("call strcmp!, value1={}, value2={}", rcx_value, rdx_value);
                    break;
                }
                case 0x00007FF75075C7B2: {
                    // printf
                    PrintRegs();

                    char rcx_value[20];
                    CHECK_ERR(uc_mem_read(uc_, regs_.rcx_, rcx_value, 20));

                    regs_.rip_ = 0x00007FF7507BA4D2;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RIP, &regs_.rip_));

                    regs_.rsp_ += 8 * 1;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RSP, &regs_.rsp_));

                    // 00007FF7507BA4D2
                    std::println("call printf!, show={}", rcx_value);
                    break;
                }
                case 0x00007FF7507A431D:{
                    // printf
                    PrintRegs();

                    char rcx_value[20];
                    CHECK_ERR(uc_mem_read(uc_, regs_.rcx_, rcx_value, 20));

                    regs_.rip_ = 0x00007FF7507BA4C7;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RIP, &regs_.rip_));

                    regs_.rsp_ += 8 * 1;
                    CHECK_ERR(uc_reg_write(uc_, UC_X86_REG_RSP, &regs_.rsp_));

                    // 00007FF7507BA4D2
                    std::println("call printf!, show={}", rcx_value);
                    break;
                }
            }

            if (const auto err = uc_emu_start(uc_, regs_.rip_, 0xffffffffffffffff, 0, 1);
                err != UC_ERR_OK) {
                std::println("Exception with error returned {}: {}",
                    static_cast<unsigned int>(err), uc_strerror(err));
                PrintRegs();
                PrintStack(regs_.rsp_);
                throw std::runtime_error("error!");
            }
            ReadRegs();
        }
    }
};

int main(int argc, char **argv, char **envp) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));

    X64Emulator emulator;
    emulator.LoadSegments(segs);
    emulator.WriteRegs();
    emulator.Run();


    system("pause");
    return 0;
}
