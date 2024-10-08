#define NAMEOF_ENUM_RANGE_MAX ZYDIS_REGISTER_MAX_VALUE
#include <algorithm>
#include <chrono>
#include <map>
#include <print>
#include <ranges>
#include <stack>
#include <Zydis/Zydis.h>

#include "../Utils/Emulator.h"
#include "../Utils/RapidMemoryDumper.h"

using RuntimeAddressType = uint64_t;
using FileOffsetType     = uint64_t;
using BytesType          = std::vector<uint8_t>;
using BranchIdType       = uint64_t;

extern ZydisDisassembledInstruction GetInstFromBytes(std::span<uint8_t> Bytes, RuntimeAddressType RuntimeAddr);

extern RuntimeAddressType GetJccTargetAddress(const ZydisDisassembledInstruction &Inst);

struct InstructionWithData {
    ZydisDisassembledInstruction Instruction;
    BytesType                    Bytes;
};

struct BranchInfo {
    BranchIdType       branch_id_       = 0;
    FileOffsetType     file_offset_     = 0;
    RuntimeAddressType runtime_address_ = 0;
};

struct TraveledInfo {
    bool               has_target_jmp_  = false;
    RuntimeAddressType runtime_address_ = 0;
    RuntimeAddressType target_addr_     = 0;
};

uint64_t MaxBranchId = 0;

std::map<RuntimeAddressType, std::vector<InstructionWithData> > BlockMap;

std::string GetInstructionDetailsString(const ZydisDisassembledInstruction &Inst) {
    return std::format("[0x{:016X}]: {:<32s}", Inst.runtime_address, Inst.text);
}

auto IsJmp(const ZydisDisassembledInstruction &Inst) {
    return Inst.info.mnemonic == ZYDIS_MNEMONIC_JMP;
}

auto IsJcc(const ZydisDisassembledInstruction &Inst) {
    if (Inst.text[0] != 'j') {
        return false;
    }
    if (IsJmp(Inst)) {
        return true;
    }
    const auto total = Inst.info.operand_count;
    for (int i = 0; i < total; i++) {
        if (Inst.operands[i].reg.value == ZYDIS_REGISTER_EFLAGS) {
            return true;
        }
    }
    return false;
}

bool InBlackList(const ZydisDisassembledInstruction &Inst) {
    if (Inst.info.mnemonic == ZYDIS_MNEMONIC_AAA ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_AAD ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_AAS ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_ARPL ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_BOUND ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_DAS ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_LAHF ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_LODSB ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_INT ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_INT1 ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_INT3 ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_OUTSB ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_OUTSD ||
        Inst.info.mnemonic == ZYDIS_MNEMONIC_ROL
    ) {
        return true;
    }

    return false;
}

auto CreateJmp(RuntimeAddressType RuntimeAddr, RuntimeAddressType TargetAddr) {
    ZydisEncoderRequest req {};
    req.machine_mode      = ZYDIS_MACHINE_MODE_LEGACY_32;
    req.mnemonic          = ZYDIS_MNEMONIC_JMP;
    req.operand_count     = 1;
    req.operands[0].type  = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[0].imm.u = TargetAddr;

    BytesType bytes(5, '\0');
    ZyanUSize expectedBytes = 5;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstructionAbsolute(&req, bytes.data(), &expectedBytes, RuntimeAddr))) {
        throw std::runtime_error("CreateJmp: ZydisEncoderEncodeInstructionAbsolute failed");
    }
    return bytes;
}

void DoBasicClean(std::vector<InstructionWithData> &InstWithData) {
    for (int i = 0; i < InstWithData.size(); ++i) {
        const auto &[inst, bytes] = InstWithData.at(i);

        // remove like this
        // call [eip+5]
        // add [esp], 5
        // ret
        while (inst.info.mnemonic == ZYDIS_MNEMONIC_RET) {
            const int indexCall = i - 2; // call xxxx
            if (indexCall < 0) {
                break;
            }
            if (InstWithData.at(indexCall).Instruction.info.mnemonic != ZYDIS_MNEMONIC_CALL
                || InstWithData.at(indexCall).Instruction.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                break;
            }
            if (GetJccTargetAddress(InstWithData.at(indexCall).Instruction) != InstWithData.at(indexCall + 1).Instruction.runtime_address) {
                break;
            }

            InstWithData.erase(InstWithData.begin() + indexCall, InstWithData.begin() + i + 1);
            i -= 3;
            break;
        }

        // replace like this
        // jnz 0x10000000
        // jz  0x10000000
        // with
        // jmp 0x10000000
        while (inst.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {
            int indexJz = i - 1; // jz xxxx
            if (indexJz < 0) {
                break;
            }

            if (InstWithData.at(indexJz).Instruction.info.mnemonic != ZYDIS_MNEMONIC_JZ) {
                break;
            }

            if (GetJccTargetAddress(InstWithData.at(indexJz).Instruction) != GetJccTargetAddress(InstWithData.at(i).Instruction)) {
                break;
            }

            // replace with jmp xxxx
            InstWithData.erase(InstWithData.begin() + indexJz, InstWithData.begin() + i + 1);
            i -= 2;

            auto jmpBytes = CreateJmp(inst.runtime_address, GetJccTargetAddress(inst));
            auto jmp      = GetInstFromBytes(jmpBytes, inst.runtime_address);
            InstWithData.emplace_back(jmp, jmpBytes);
            break;
        }
    }
}

RuntimeAddressType GetJccTargetAddress(const ZydisDisassembledInstruction &Inst) {
    if (IsJmp(Inst)) {
        // assert(Inst.info.length == 5 && "this jmp is near or far instruction");
        return Inst.operands[0].imm.value.u + Inst.info.length + Inst.runtime_address;
    }
    // assert(Inst.info.length == 6 && "this jcc is near or far instruction");
    return Inst.operands[0].imm.value.u + Inst.info.length + Inst.runtime_address;
}

ZydisDisassembledInstruction GetInstFromBytes(std::span<uint8_t> Bytes, RuntimeAddressType RuntimeAddr) {
    ZydisDisassembledInstruction inst;
    if (ZYAN_FAILED(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, RuntimeAddr, Bytes.data(), Bytes.size(), &inst))) {
        throw std::runtime_error("GetInstFromBytes: ZydisDisassembleIntel failed");
    }
    return inst;
}

std::optional<ZydisDisassembledInstruction>
GetInst(FileOffsetType FileOffset, RuntimeAddressType RuntimeAddr, const std::span<uint8_t> Code) {
    if (FileOffset + 32 > Code.size()) {
        std::println("not normal instruction: 0x{:016X}", RuntimeAddr);
        return std::nullopt;
    }
    ZydisDisassembledInstruction inst;
    if (ZYAN_FAILED(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, RuntimeAddr, Code.data() + FileOffset, 32, &inst))) {
        std::println("not normal instruction: 0x{:016X}", RuntimeAddr);
        return std::nullopt;
    }
    return inst;
}

std::optional<ZydisDisassembledInstruction>
SkipUntilJccInst(FileOffsetType FileOffset, RuntimeAddressType RuntimeAddr, const std::span<uint8_t> Code) {
    bool       failed       = false;
    const auto startAddress = RuntimeAddr;

    std::optional<ZydisDisassembledInstruction> optInst;
    for (;;) {
        optInst = GetInst(FileOffset, RuntimeAddr, Code);
        if (!optInst) {
            failed = true;
            break;
        }

        auto &inst = optInst.value();
        BlockMap[startAddress].emplace_back(inst, BytesType(Code.begin() + FileOffset, Code.begin() + FileOffset + inst.info.length));

        if (InBlackList(inst)) {
            std::println("in black list: 0x{:016X}, {}", RuntimeAddr, GetInstructionDetailsString(inst));
            failed = true;
            break;
        }

        // std::println("{}", GetInstructionDetailsString(inst));
        if (IsJcc(inst)) {
            break;
        }
        FileOffset += inst.info.length;
        RuntimeAddr += inst.info.length;
    }

    if (failed) {
        return std::nullopt;
    }

    return optInst;
}

void DoAnalyze(RuntimeAddressType StartAddr, RuntimeAddressType SegmentAddr, const std::span<uint8_t> Code) {
    // step1 get all branch, split by jcc instruction
    std::vector<TraveledInfo> traveled;
    std::stack<BranchInfo>    branchStack;
    branchStack.push({ 0, StartAddr - SegmentAddr, StartAddr });
    for (; !branchStack.empty();) {
        auto [branch_id_, file_offset_, runtime_address_] = branchStack.top();
        branchStack.pop();

        std::println("[process]: {} start, remain: {}", branch_id_, branchStack.size());

        // check traveled address
        if (std::ranges::find_if(traveled, [&runtime_address_](const TraveledInfo &info) {
            return info.runtime_address_ == runtime_address_;
        }) != traveled.end()) {
            std::println("already traveled: jmp 0x{:016X}", runtime_address_);
            traveled.emplace_back(true, 0, runtime_address_);
            continue;
        }
        traveled.emplace_back(false, runtime_address_, 0);

        // emulate instruction until jcc
        // make new branch from jcc
        auto optInst = SkipUntilJccInst(file_offset_, runtime_address_, Code);
        if (!optInst) {
            // if 'SkipUntilJccInst' failed, remove this block, remove traveled address
            BlockMap.erase(runtime_address_);
            traveled.pop_back(); // not care
            continue;
        }
        auto &inst       = optInst.value();
        auto  targetAddr = GetJccTargetAddress(inst);

        // check jz and jnz to same address
        while (inst.info.mnemonic == ZYDIS_MNEMONIC_JZ) {
            auto optInstNext = GetInst(inst.runtime_address + inst.info.length - SegmentAddr, inst.runtime_address + inst.info.length, Code);
            if (!optInstNext) {
                break;
            }
            auto &instNext = optInstNext.value();
            if (instNext.info.mnemonic != ZYDIS_MNEMONIC_JNZ) {
                break;
            }

            auto targetAddrNext = GetJccTargetAddress(instNext);
            if (targetAddrNext != targetAddr) {
                break;
            }

            BlockMap.at(runtime_address_).emplace_back(instNext);
            break;
        }
        DoBasicClean(BlockMap.at(runtime_address_));
        inst = BlockMap.at(runtime_address_).back().Instruction;

        std::println("----------------cleaned-------------------------------");
        for (const auto &[Instruction, Bytes]: BlockMap.at(runtime_address_)) {
            std::println("{}", GetInstructionDetailsString(Instruction));
        }
        std::println("----------------cleaned end---------------------------");

        // add two branch blocks
        std::println("[make branch] {} To 0x{:016X}", ++MaxBranchId, targetAddr);
        branchStack.emplace(MaxBranchId, targetAddr - SegmentAddr, targetAddr);
        if (IsJmp(inst)) {
            continue;
        }
        std::println("[make branch] {} To 0x{:016X}", ++MaxBranchId, inst.runtime_address + inst.info.length);
        branchStack.emplace(MaxBranchId, inst.runtime_address + inst.info.length - SegmentAddr, inst.runtime_address + inst.info.length);
    }


    // step2, map all addr from 'traveled', merge all instruction(remove jmp)
    // rebuild control flow
    // WARN, more jmp inst will be generated
    BytesType newdata;
    uint64_t  offsetOfNewInst = 0;
    for (auto [has_target_jmp_, runtime_address_, target_addr_]: traveled) {
        if (has_target_jmp_) {
            newdata.insert(newdata.end(), { 0xe9, 0x00, 0x00, 0x00, 0x00 });
            std::println("jmp 0x{:016X}", target_addr_);
            continue;
        }
        for (auto  addr_ = runtime_address_;
             auto &[inst, bytes]: BlockMap.at(addr_)) {
            if (IsJmp(inst)) {
                addr_ = GetJccTargetAddress(inst);
                continue;
            }
            std::println("{}", GetInstructionDetailsString(inst));
            for (int i = 0; i < inst.info.length; ++i) {
                newdata.emplace_back(bytes[i]);
            }
        }
    }
    for (unsigned char & i : newdata) {
        std::print("{:02X} ", i);
    }
}

BytesType DoPatch(FileOffsetType SegmentBegin, const std::span<uint8_t> Code) {
    BytesType newData(Code.size(), 0x90);
    for (auto &[k, v]: BlockMap) {
        for (auto &[inst, bytes]: v) {
            for (int i = 0; i < inst.info.length; ++i) {
                newData[inst.runtime_address - SegmentBegin + i] = bytes[i];
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

    auto               buffer = ReadFileBinary("D:/我的文件/IDM/下载文件-IDM/destination - 副本_00411000text.bin");
    std::span<uint8_t> Code(reinterpret_cast<uint8_t *>(buffer.data()), buffer.size());
    DoAnalyze(0x004140D7, 0x00411000, Code);

    writeFile("deeeeee.bin", DoPatch(0x00411000, Code));
}
