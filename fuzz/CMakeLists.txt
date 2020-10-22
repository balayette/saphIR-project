include(Fmt)

add_executable(fuzz
	src/fuzz.cc
	src/harness.cc
	src/mutator.cc
)

target_include_directories(emu
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(fuzz
	PRIVATE
		emu
		utils
		fmt::fmt)
