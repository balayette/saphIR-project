add_library(utils STATIC
        src/assert.cc
        src/symbol.cc
        src/fs.cc
)

target_include_directories(utils
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(utils
        PUBLIC
                fmt::fmt
)
