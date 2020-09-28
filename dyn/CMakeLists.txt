include(CapstoneKeystone)
include(Fmt)

add_library(emu STATIC
        src/base-emu.cc
        src/emu.cc
        src/unicorn-emu.cc
)

target_include_directories(emu
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(emu
        PUBLIC
                lifter
                elf_loader
                keystone
                unicorn
                pthread
        PRIVATE
                IR
                utils
                fmt::fmt
)

add_executable(dyn
        src/main.cc
)

add_executable(harness
        src/harness.cc
)

target_link_libraries(dyn
        PRIVATE
                emu
                utils
)

target_link_libraries(harness
        PRIVATE
                emu
                utils
)
