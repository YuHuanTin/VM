//
// Created by AFETT on 2024/8/31.
//

#ifndef RAPIDMEMORYLOADER_H
#define RAPIDMEMORYLOADER_H

struct SEG_MAP {
    uint64_t         base;
    uint64_t         size;
    std::string_view file_name;
};

struct SEG_MAP_X86 {
    uint32_t         base;
    uint32_t         size;
    std::string_view file_name;
};

template<typename SEG_MAP_MEM_MODE = SEG_MAP_MEM>
class RapidMemoryLoader {
    std::vector<SEG_MAP_MEM_MODE> seg_map_;

public:
    explicit RapidMemoryLoader(const std::string_view DumpFilesDirectory) {
        const std::filesystem::path directory(DumpFilesDirectory);
        if (!std::filesystem::exists(directory)) {
            std::println("Dump files directory not exists");
            return;
        }

        for (const auto &entry: std::filesystem::directory_iterator(directory)) {
            auto fileNamePath = entry.path().filename();
            auto fileNameStr  = fileNamePath.string();
            if (fileNamePath.extension() != ".bin" || !fileNameStr.starts_with("ba") || 2 + 16 != fileNameStr.find("si")) {
                continue;
            }
            const auto dumpBase = std::stoull(fileNameStr.substr(2, 16), nullptr, 16);
            const auto dumpSize = std::stoull(fileNameStr.substr(2 + 16 + 2, 16), nullptr, 16);

            auto buffer = ReadFileBinary(entry.path().string());
            assert(buffer.size() == dumpSize && "Segment size mismatch?");

            seg_map_.emplace_back(dumpBase, dumpSize, buffer);
        }
    }

    template<typename SEG_MAP_MODE>
    explicit RapidMemoryLoader(std::span<SEG_MAP_MODE> Segs) {
        AppendMoreSegs(Segs);
    }

    template<typename SEG_MAP_MODE>
    void AppendMoreSegs(SEG_MAP_MODE Segs) {
        auto buffer = ReadFileBinary(Segs.file_name);
        assert(buffer.size() == Segs.size && "Segment size mismatch?");

        seg_map_.emplace_back(Segs.base, Segs.size, buffer);
    }

    std::span<SEG_MAP_MEM_MODE> GetSegMap() { return seg_map_; }

    ~RapidMemoryLoader() = default;
};


#endif //RAPIDMEMORYLOADER_H
