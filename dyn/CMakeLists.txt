include(CapstoneKeystone)
include(Fmt)

add_library(emu STATIC
        src/base-emu.cc
        src/emu.cc
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
        PRIVATE
                IR
                utils
                fmt::fmt
)

add_executable(dyn
        src/main.cc
)

target_link_libraries(dyn
        PRIVATE
                emu
                utils
)
