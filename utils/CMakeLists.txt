add_library(utils STATIC
        src/assert.cc
        src/symbol.cc
)

target_include_directories(utils
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)
