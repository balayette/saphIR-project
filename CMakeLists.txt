cmake_minimum_required(VERSION 3.10)

project (saphIR
        VERSION 1.0
        DESCRIPTION "The saphIR project"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(compiler/)
add_subdirectory(saphIR/)
add_subdirectory(utils/)
