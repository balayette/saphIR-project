include(FindPkgConfig)

pkg_check_modules(CAPSTONE REQUIRED capstone)
pkg_check_modules(KEYSTONE REQUIRED keystone)

add_library(lifter STATIC
        src/lifter.cc
        src/disas.cc
)

target_include_directories(lifter
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(lifter
        PUBLIC IR
        PUBLIC utils

        PRIVATE ${CAPSTONE_LIBRARIES}
        PRIVATE ${KEYSTONE_LIBRARIES}
)

add_executable(lifter_main
        src/main.cc
)

target_link_libraries(lifter_main
        PRIVATE lifter
)
