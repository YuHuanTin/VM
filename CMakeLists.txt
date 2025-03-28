cmake_minimum_required(VERSION ${CMAKE_VERSION})
project(VM)

set(CMAKE_CXX_STANDARD 26)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    set(IS_CLANG_CL TRUE)
endif ()


find_package(PkgConfig REQUIRED)
find_package(zydis CONFIG REQUIRED)

link_libraries(Zydis::Zydis)

pkg_check_modules(unicorn_ REQUIRED IMPORTED_TARGET unicorn)
link_libraries(PkgConfig::unicorn_)

if (IS_CLANG_CL)
    add_compile_options(/clang:-Wall -Wextra -Wpedantic -Wconversion)

    if (ENABLE_ASAN)
        link_directories(D:/LLVM/lib/clang/19/lib/windows)
        link_libraries(clang_rt.asan-x86_64.lib)
        add_compile_options(-fsanitize=address -MT)
    endif ()
else ()
    # if msvc
    add_compile_options(/utf-8)
endif ()


add_subdirectory(V1)
add_subdirectory(V2)
add_subdirectory(V4)
add_subdirectory(OEPTracker)
add_subdirectory(EmulatorTest)
add_subdirectory(OllvmDeobf)