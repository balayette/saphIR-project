include(CapstoneKeystone)

add_library(lifter STATIC
        src/lifter.cc
        src/disas.cc
)

target_include_directories(lifter
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(lifter
        PUBLIC
                IR
                utils

        PRIVATE
                capstone-static
)

add_executable(lifter_main
        src/main.cc
)

target_link_libraries(lifter_main
        PRIVATE
                lifter
                keystone
)
