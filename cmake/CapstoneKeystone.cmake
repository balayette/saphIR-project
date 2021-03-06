include(FetchContent)

# Capstone and Keystone do not have up to date packages,
# so we have to fetch and build them.
# The configuration step is pretty tricky because Capstone/Keystone define
# broken targets.
# https://github.com/vtil-project/VTIL-Core/blob/master/cmake/IncludeDeps.cmake

message(STATUS "Pulling and configuring capstone and keystone")

set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build capstone tests" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build shared capstone" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build cstool" FORCE)

set(BUILD_LIBS_ONLY ON CACHE BOOL "Build only libs" FORCE)

set(UNICORN_BUILD_SHARED OFF CACHE BOOL "Build shared unicorn" FORCE)
set(UNICORN_ARCH "aarch64" CACHE STRING "unicorn archs" FORCE)

FetchContent_Declare(
        Capstone
        GIT_REPOSITORY https://github.com/aquynh/capstone/
        GIT_TAG        4.0.2
)
FetchContent_Declare(
        Keystone
        GIT_REPOSITORY https://github.com/keystone-engine/keystone
        GIT_TAG 03d5d24a008e90210359abbd7b7071efd28c8abe
)
FetchContent_Declare(
        Unicorn
        GIT_REPOSITORY https://github.com/unicorn-engine/unicorn
        GIT_TAG 21235916b9f4f5853da2a24b74b3eed86195d607
)
FetchContent_MakeAvailable(Capstone Keystone Unicorn)

get_target_property(Capstone_SOURCE_DIR capstone-static SOURCE_DIR)
set_property(TARGET capstone-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Capstone_SOURCE_DIR}/include)

get_target_property(Keystone_SOURCE_DIR keystone SOURCE_DIR)
get_target_property(Keystone_INCLUDE_DIRS keystone INCLUDE_DIRECTORIES)
set_property(TARGET keystone PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Keystone_INCLUDE_DIRS} ${Keystone_SOURCE_DIR}/include)


get_target_property(Unicorn_SOURCE_DIR unicorn SOURCE_DIR)
set_property(TARGET unicorn PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Unicorn_INCLUDE_DIRS} ${Unicorn_SOURCE_DIR}/include)
