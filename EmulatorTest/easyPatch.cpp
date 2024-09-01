//
// Created by AFETT on 2024/9/1.
//


#include <locale>
#include <vector>

#include "../Utils/RapidMemoryPatcher.h"

int main(int argc, char *argv[]) {
    // disable output buffering
    setvbuf(stdout, nullptr, _IONBF, 0);

    // setting global encoding utf-8
    std::locale::global(std::locale("zh_CN.UTF-8"));


    RipperMemoryPatcher rip { 13820 };
    // E8 00 00 00 00 83 04 24 05 C3
    std::vector<uint8_t> pattern = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xC3 };
    std::vector<uint8_t> replace = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    rip.PatcherMemory(0x00401000, 0x00423000, pattern, replace);
}
