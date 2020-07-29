include(FetchContent)

message(STATUS "Pulling and configuring fmt")

FetchContent_Declare(
        Fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt
        GIT_TAG 7.0.1
)
FetchContent_MakeAvailable(Fmt)
