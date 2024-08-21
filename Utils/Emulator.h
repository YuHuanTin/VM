//
// Created by AFETT on 2024/8/21.
//

#ifndef EMULATOR_H
#define EMULATOR_H

#include <functional>

#include "def.h"

class X64Emulator {
private:
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

    // 保留 0 作为所有代码的观察者
    std::unordered_map<uint64_t, std::function<void(X64Emulator *)> > observers_;

public:
    uc_engine *uc_ { nullptr };
    REGS       regs_;

    explicit X64Emulator(const REGS &Regs) : regs_(Regs) {
        std::println("Emulate AMD64 machine code");
        CHECK_ERR(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_));

        RegisterObserver(0, [](const X64Emulator *Emu) {
            uint8_t code[32];
            CHECK_ERR(uc_mem_read(Emu->uc_, Emu->regs_.rip_, code, 32));
            ZydisDisassembledInstruction insn;
            ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Emu->regs_.rip_, code, 32, &insn);
            std::println("{}", insn.text);
        });
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

    void RegisterObserver(const uint64_t ObserverAddress, std::function<void(X64Emulator *)> &&Observer) {
        observers_[ObserverAddress] = Observer;
    }

    void Run() {
        int count = 0;
        for (;;) {
            count++;

            if (observers_.contains(regs_.rip_))
                observers_.at(regs_.rip_)(this);
            observers_[0](this);

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

#endif //EMULATOR_H
