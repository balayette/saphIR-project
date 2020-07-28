add_library(elf_loader STATIC
        src/elf.cc
)

target_link_libraries(elf_loader
        PUBLIC
                utils
        PRIVATE
                fmt::fmt
)

target_include_directories(elf_loader
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(readelf
        src/readelf.cc
)

target_link_libraries(readelf
        PRIVATE
                elf_loader
)
