//
// Created by AFETT on 2024/8/21.
//

#ifndef EMULATOR_H
#define EMULATOR_H


#include <filesystem>
#include <functional>

#include "def.h"
#include "unicorn/unicorn.h"

template<typename T>
class Emulator {
    friend T;

    Emulator() = default;

    void RunInner(this auto &&self) {
        auto CurrentIP = self.GetCurrentIP();
        if (self.observers_.contains(CurrentIP)) {
            self.ReadRegsSyncCheck();
            self.observers_[CurrentIP](&self);
            self.WriteRegsSyncCheck();
        }
        if (self.observers_.contains(0)) {
            self.ReadRegsSyncCheck();
            self.observers_[0](&self);
            self.WriteRegsSyncCheck();
        }

        if (const auto err = uc_emu_start(self.uc_, CurrentIP, 0xffffffffffffffff, 0, 1);
            err != UC_ERR_OK) {
            std::println("Exception with error returned {}: {}",
                static_cast<unsigned int>(err), uc_strerror(err));
            self.PrintRegs();
            self.PrintStack();
            throw std::runtime_error("error!");
        }
        self.ReadRegs();
    }

public:
    virtual ~Emulator() = default;

    /**
     * 写入所有寄存器的值，从 regs_
     */
    void WriteRegs(this auto &&self) {
        CHECK_ERR(uc_reg_write_batch(self.uc_, self.reg_batch_, self.reg_value_batch_, std::size(self.reg_value_batch_)));
    }

    void WriteRegsSyncCheck(this auto &&self) {
        if (self.optional_AutoAutoSyncRegs_) {
            self.WriteRegs();
        }
    }

    /**
     * 读取所有寄存器的值，写到 regs_
     */
    void ReadRegs(this auto &&self) {
        CHECK_ERR(uc_reg_read_batch(self.uc_, self.reg_batch_, self.reg_value_batch_, std::size(self.reg_value_batch_)));
    }

    void ReadRegsSyncCheck(this auto &&self) {
        if (self.optional_AutoAutoSyncRegs_) {
            self.ReadRegs();
        }
    }

    template<ReqMemLoaderable SEG_MAP_MEM_MODE>
    void LoadSegments(this auto &&self, std::span<SEG_MAP_MEM_MODE> Segs) {
        // map memory for this emulation
        for (auto [base_, size_, buffer]: Segs) {
            // assert(buffer.size() == size_ && "Segment size mismatch?");

            // map memory for this emulation
            CHECK_ERR(uc_mem_map(self.uc_, base_, size_, UC_PROT_ALL));

            // write machine code to be emulated to memory
            CHECK_ERR(uc_mem_write(self.uc_, base_, buffer.data(), buffer.size()));

            if (self.optional_DetailOutput_)
                std::println("Segment [0x{:x}, 0x{:x}]", base_, base_ + size_);
        }
    }

    template<typename NumberType>
    void Run(this auto &&self, NumberType Until, const bool RunNextWhenUntil = false) {
        while (self.GetCurrentIP() != Until) {
            self.RunInner();
        }
        if (RunNextWhenUntil) {
            self.RunInner();
        }
    }
};

class X64Emulator : public Emulator<X64Emulator> {
    friend Emulator;

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
    bool       optional_AutoAutoSyncRegs_;
    bool       optional_DetailOutput_;


    explicit X64Emulator(const REGS &Regs, const bool AutoSyncRegs = true, const bool RegisterInstructionOutput = true, const bool DetailOutput = true)
        : regs_(Regs), optional_AutoAutoSyncRegs_(AutoSyncRegs), optional_DetailOutput_(DetailOutput) {
        CHECK_ERR(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_));

        if (optional_DetailOutput_) {
            std::println("Emulate AMD64 machine code");
        }

        if (RegisterInstructionOutput) {
            RegisterObserver(0, [](const X64Emulator *Emu) {
                uint8_t code[32];
                CHECK_ERR(uc_mem_read(Emu->uc_, Emu->regs_.rip_, code, 32));
                ZydisDisassembledInstruction insn;
                ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, Emu->regs_.rip_, code, 32, &insn);
                std::println("[0x{:016X}], {}", insn.runtime_address, insn.text);
            });
        }

        WriteRegs();
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

    void PrintStack() const {
        uint64_t Rsp = regs_.rsp_;

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

    [[nodiscard]] auto GetCurrentIP() const {
        return regs_.rip_;
    }

    ~X64Emulator() override {
        uc_close(uc_);
    }
};

class X86Emulator : public Emulator<X86Emulator> {
    friend Emulator;

    int reg_batch_[10] = {
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_ESI, UC_X86_REG_EDI,
        UC_X86_REG_EIP, UC_X86_REG_EFLAGS
    };
    void *reg_value_batch_[10] = {
        &regs_.eax_, &regs_.ebx_, &regs_.ecx_, &regs_.edx_,
        &regs_.ebp_, &regs_.esp_, &regs_.esi_, &regs_.edi_,
        &regs_.eip_, &regs_.eflags_
    };

    // 保留 0 作为所有代码的观察者
    std::unordered_map<uint32_t, std::function<void(X86Emulator *)> > observers_;

public:
    uc_engine *uc_ { nullptr };
    REGS_X86   regs_;
    bool       optional_AutoAutoSyncRegs_;
    bool       optional_DetailOutput_;

    explicit X86Emulator(const REGS_X86 &Regs, const bool AutoSyncRegs = true, const bool RegisterInstructionOutput = true, const bool DetailOutput = true)
        : regs_(Regs), optional_AutoAutoSyncRegs_(AutoSyncRegs), optional_DetailOutput_(DetailOutput) {
        CHECK_ERR(uc_open(UC_ARCH_X86, UC_MODE_32, &uc_));

        if (optional_DetailOutput_) {
            std::println("Emulate Intel32 machine code");
        }

        if (RegisterInstructionOutput) {
            RegisterObserver(0, [](const X86Emulator *Emu) {
                uint8_t code[32];
                CHECK_ERR(uc_mem_read(Emu->uc_, Emu->regs_.eip_, code, 32));
                ZydisDisassembledInstruction insn;
                ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, Emu->regs_.eip_, code, 32, &insn);
                std::println("[0x{:08X}], {}", insn.runtime_address, insn.text);
            });
        }

        WriteRegs();
    }

    void PrintRegs() {
        std::println(
            "eax: 0x{:08X}\nebx: 0x{:08X}\necx: 0x{:08X}\nedx: 0x{:08X}\n"
            "ebp: 0x{:08X}\nesp: 0x{:08X}\nesi: 0x{:08X}\nedi: 0x{:08X}\n"
            "eip: 0x{:08X}\neflags: 0x{:08X}",
            regs_.eax_, regs_.ebx_, regs_.ecx_, regs_.edx_,
            regs_.ebp_, regs_.esp_, regs_.esi_, regs_.edi_,
            regs_.eip_, regs_.eflags_);
    }

    void PrintStack() const {
        uint32_t Esp = regs_.esp_;

        uint32_t val;
        for (int i = 0; i < 10; i++) {
            uc_mem_read(uc_, Esp, &val, 4);
            std::println("|0x{:08X}|", val);
            Esp += 4;
        }
    }

    void RegisterObserver(const uint32_t ObserverAddress, std::function<void(X86Emulator *)> &&Observer) {
        observers_[ObserverAddress] = Observer;
    }

    [[nodiscard]] auto GetCurrentIP() const {
        return regs_.eip_;
    }

    ~X86Emulator() override {
        uc_close(uc_);
    }
};


#endif //EMULATOR_H
