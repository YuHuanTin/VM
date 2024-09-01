#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE
#include <algorithm>
#include <chrono>
#include <map>
#include <print>
#include <queue>
#include <ranges>
#include <Zydis/Zydis.h>

#include "../Utils/Emulator.h"
#include "../Utils/RapidMemoryDumper.h"

std::string GetInstructionDetailsString(ZydisDisassembledInstruction &Instruction) {
    return std::format("[0x{:016X}]: {:<32s}", Instruction.runtime_address, Instruction.text);
}

auto IsJmp(const ZydisDisassembledInstruction &Insn) {
    return Insn.info.mnemonic == ZYDIS_MNEMONIC_JMP;
}

auto IsJcc(const ZydisDisassembledInstruction &Insn) {
    if (Insn.text[0] != 'j') {
        return false;
    }
    if (IsJmp(Insn)) {
        return true;
    }
    const auto total = Insn.info.operand_count;
    for (int i = 0; i < total; i++) {
        if (Insn.operands[i].reg.value == ZYDIS_REGISTER_EFLAGS) {
            return true;
        }
    }
    return false;
}

bool InBlackList(const ZydisDisassembledInstruction &Insn) {
    if (Insn.info.mnemonic == ZYDIS_MNEMONIC_AAA ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_AAD ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_AAS ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_ARPL ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_BOUND ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_DAS ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_LAHF ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_LODSB ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_INT ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_INT1 ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_INT3 ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_OUTSB ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_OUTSD ||
        Insn.info.mnemonic == ZYDIS_MNEMONIC_ROL
    ) {
        return true;
    }

    return false;
}

bool InBlackAddr(const ZydisDisassembledInstruction &Insn) {
    std::vector<std::pair<uint64_t, uint64_t> > BlackList = {
        { 0x0041B7AC, 0x0041B97B }
    };
    std::vector<uint64_t> SingleBlackList = {
        0x0041435C, 0x000000000041474C, 0x0000000000414A66, 0x0000000000414A5A, 0x0000000000414BB4
    };
    return std::ranges::any_of(BlackList, [&](auto item) { return item.first <= Insn.runtime_address && Insn.runtime_address <= item.second; }) ||
           std::ranges::any_of(SingleBlackList, [&](auto item) { return item == Insn.runtime_address; });
}

/**
 * seg RVA and runtime address
 */
struct BranchInfo {
    uint64_t block_start_rva_;
    uint64_t block_runtime_address_;
    uint64_t branch_id_;
};

using RuntimeAddressDef = uint64_t;

uint64_t BranchId = 0;

std::queue<BranchInfo> BranchQueue;

std::map<RuntimeAddressDef, std::vector<ZydisDisassembledInstruction> > BlockMap;

std::vector<RuntimeAddressDef> traveledAddress;

void DoBasicClean(std::vector<ZydisDisassembledInstruction> &Insn) {
    for (int i = 0; i < Insn.size(); ++i) {
        const auto &insn = Insn.at(i);

        while (insn.info.mnemonic == ZYDIS_MNEMONIC_RET) {
            int size      = Insn.size();
            int indexCall = size - 2 - 1; // call xxxx
            if (indexCall < 0) {
                break;
            }

            if (Insn.at(indexCall).info.mnemonic != ZYDIS_MNEMONIC_CALL) {
                break;
            }
            if (Insn.at(indexCall).operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                break;
            }
            if (Insn.at(indexCall).operands[0].imm.value.u + Insn.at(indexCall).runtime_address + Insn.at(indexCall).info.length
                != Insn.at(indexCall + 1).runtime_address) {
                break;
            }


            Insn.erase(Insn.begin() + i - 2, Insn.begin() + i + 1);
            i--;
            break;
        }

        while (insn.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {
            int size    = Insn.size();
            int indexJz = size - 2; // call xxxx
            if (indexJz < 0) {
                break;
            }

            if (Insn.at(indexJz).info.mnemonic != ZYDIS_MNEMONIC_JZ) {
                break;
            }

            if (Insn.at(indexJz).operands[0].imm.value.u - Insn.at(indexJz).info.length
                != Insn.at(indexJz + 1).operands[0].imm.value.u) {
                break;
            }

            for (int j = 0; j < 2; ++j) {
                Insn.erase(Insn.begin() + i - 1);
            }
            i--;
            break;
        }
    }
}

std::optional<ZydisDisassembledInstruction>
GetJccInstruction(uint64_t QRVA, uint64_t QRunAddr, const std::span<uint8_t> Code) {
    if (QRVA + 32 > Code.size()) {
        std::println("not normal instruction: 0x{:016X}", QRunAddr);
        return std::nullopt;
    }

    bool           failed       = false;
    const uint64_t startAddress = QRunAddr;

    ZydisDisassembledInstruction insn;
    for (;;) {
        std::span<uint8_t> buffer = Code.subspan(QRVA, 32);

        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, QRunAddr, buffer.data(), buffer.size(), &insn))) {
            std::println("not normal instruction: 0x{:016X}", QRunAddr);
            failed = true;
            break;
        }
        BlockMap[startAddress].emplace_back(insn);

        if (InBlackList(insn)) {
            std::println("in black list: 0x{:016X}, {}", QRunAddr, GetInstructionDetailsString(insn));
            failed = true;
            break;
        }

        if (InBlackAddr(insn)) {
            std::println("in black addr: 0x{:016X}, {}", QRunAddr, GetInstructionDetailsString(insn));
            failed = true;
            break;
        }

        if (insn.info.mnemonic == ZYDIS_MNEMONIC_RET) {
            break;
        }

        if (IsJcc(insn)) {
            break;
        }

        QRVA += insn.info.length;
        QRunAddr += insn.info.length;
        std::println("{}", GetInstructionDetailsString(insn));
    }

    if (failed) {
        BlockMap.erase(startAddress);
        return std::nullopt;
    }

    DoBasicClean(BlockMap[startAddress]);

    return insn;
}

void DoAnalyze(uint64_t SegRVA, uint64_t RuntimeAddress, const std::span<uint8_t> Code) {
    BranchQueue.emplace(SegRVA, RuntimeAddress, 0);
    const auto diffRVARuntime = RuntimeAddress - SegRVA;

    for (; !BranchQueue.empty();) {
        auto [blockStartRVA, blockStartRuntimeAddr, branch_id] = BranchQueue.front();
        BranchQueue.pop();
        std::println("[process]: {} start, remain: {}", branch_id, BranchQueue.size());

        // check traveled address
        if (std::ranges::contains(traveledAddress, blockStartRuntimeAddr)) {
            std::println("already traveled: 0x{:016X}", blockStartRuntimeAddr);
            continue;
        }
        traveledAddress.emplace_back(blockStartRuntimeAddr);

        // make branch
        if (auto insnOpt = GetJccInstruction(blockStartRVA, blockStartRuntimeAddr, Code);
            insnOpt.has_value()) {
            auto &insn = insnOpt.value();

            // add two branch blocks
            auto jccAddress = insn.operands[0].imm.value.u + insn.info.length + insn.runtime_address;
            std::println("[make branch] {}", ++BranchId);
            BranchQueue.emplace(jccAddress - diffRVARuntime, jccAddress, BranchId);
            if (IsJmp(insn)) {
                continue;
            }
            std::println("[make branch] {}", ++BranchId);
            BranchQueue.emplace(insn.runtime_address + insn.info.length - diffRVARuntime, insn.runtime_address + insn.info.length, BranchId);
        }
    }

    for (auto &[k, v]: BlockMap) {
        std::println("block: 0x{:016X}", k);
        for (auto &insn: v) {
            std::println("{}", GetInstructionDetailsString(insn));
        }
    }
}

std::vector<uint8_t> DoPatch(uint64_t Offset, const std::span<uint8_t> Code) {
    std::vector<uint8_t> newData(Code.size(), 0x90);
    for (auto &[k, v]: BlockMap) {
        for (auto &insn: v) {
            for (int i = 0; i < insn.info.length; ++i) {
                newData[insn.runtime_address - Offset + i] = Code[insn.runtime_address - Offset + i];
            }
        }
    }
    return newData;
}

template<typename InputType>
    requires std::is_same_v<InputType, std::string> ||
             std::is_same_v<InputType, std::vector<uint8_t> >
bool writeFile(const std::string &FilePath, InputType &&content) {
    std::fstream fs(FilePath, std::ios_base::out | std::ios_base::binary);
    if (!fs.is_open())
        return false;

    fs.write(std::bit_cast<const char *>(content.data()), content.size());
    fs.close();
    return true;
}

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));

    auto               buffer = ReadFileBinary("text.bin");
    std::span<uint8_t> Code(reinterpret_cast<uint8_t *>(buffer.data()), buffer.size());
    DoAnalyze(0x140D7 - /* PE + .textbss size */ (0x1000 + 0x10000), 0x004140D7, Code);


    writeFile("deeeeee.bin", DoPatch(0x00411000, Code));
}
