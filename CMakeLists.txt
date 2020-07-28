cmake_minimum_required(VERSION 3.10)

project (saphIR
        VERSION 1.0
        DESCRIPTION "The saphIR project"
        LANGUAGES CXX)

# Colors even when using ninja
option (FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." TRUE)
if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options (-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_CXX_FLAGS "-Wall -Wextra -pedantic -g")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

add_subdirectory(compiler/)
add_subdirectory(saphIR/)
add_subdirectory(utils/)
add_subdirectory(lifter/)
add_subdirectory(elf/)
add_subdirectory(dyn/)
