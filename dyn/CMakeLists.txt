include(CapstoneKeystone)
include(Fmt)

add_executable(dyn
        src/main.cc
        src/emu.cc
)

target_include_directories(dyn
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(dyn
        PRIVATE
                IR
                lifter
                elf_loader
                utils
                keystone
                fmt::fmt
)
