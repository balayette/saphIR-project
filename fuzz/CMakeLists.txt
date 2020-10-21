include(Fmt)

add_executable(fuzz
	src/fuzz.cc
)

target_link_libraries(fuzz
	PRIVATE
		emu
		utils
		fmt::fmt)
