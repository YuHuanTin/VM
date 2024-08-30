cmake_minimum_required(VERSION 3.29)
project(VM)

set(CMAKE_CXX_STANDARD 26)

find_package(PkgConfig REQUIRED)
find_package(zydis CONFIG REQUIRED)

link_libraries(Zydis::Zydis)

pkg_check_modules(unicorn_ REQUIRED IMPORTED_TARGET unicorn)
link_libraries(PkgConfig::unicorn_)

add_compile_options(/utf-8)
add_subdirectory(V1)
add_subdirectory(V2)
add_subdirectory(V4)
add_subdirectory(OEPTracker)
add_subdirectory(EmulatorTest)