

add_executable(V1_TestExec e1.cpp)
add_executable(V1_Emulator main.cpp)

target_link_options(V1_TestExec PRIVATE /INCREMENTAL:NO)