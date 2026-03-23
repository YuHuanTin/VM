cmake_minimum_required(VERSION 4.1.2)
set(VCPKG_TARGET_TRIPLET "x64-mingw-dynamic")
set(VCPKG_HOST_TRIPLET "x64-mingw-dynamic")

# experimental.rst
# or https://github.com/Kitware/CMake/blob/master/Help/dev/experimental.rst
set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "d0edc3af-4c50-42ea-a356-e2862fe7a444")
# to support 'import std'
set(CMAKE_CXX_MODULE_STD ON)

project(VM)

set(CMAKE_CXX_STANDARD 26)

find_package(PkgConfig REQUIRED)
find_package(zydis CONFIG REQUIRED)

link_libraries(Zydis::Zydis)

pkg_check_modules(unicorn_ REQUIRED IMPORTED_TARGET unicorn)
link_libraries(PkgConfig::unicorn_)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion)


add_subdirectory(V1)
add_subdirectory(V2)
add_subdirectory(V4)
add_subdirectory(OEPTracker)
add_subdirectory(EmulatorTest)
add_subdirectory(OllvmDeobf)

add_library(utils STATIC)
target_sources(utils
        PUBLIC
        FILE_SET cxxmods
        TYPE CXX_MODULES
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/Utils
        FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils/def.cppm
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils/Emulator.cppm
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils/RapidMemoryDumper.cppm
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils/RapidMemoryLoader.cppm
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils/RapidMemoryPatcher.cppm
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils/RapidRegisterStringParser.cppm
)