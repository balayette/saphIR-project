#include <chrono>

#include "dyn/emu.hh"
#include "fmt/format.h"

#define RESET_COUNT 100000

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fmt::print("usage: fuzzer binary");
		return 1;
	}

	utils::mapped_file file(argv[1]);
	dyn::emu emu(file, dyn::emu_params(false));

	emu.init();
	emu.setup();
	emu.run_until(0x400274);

	emu.mmu().make_clean_state();
	dyn::mmu base_mmu = emu.mmu();
	lifter::state base_state = emu.state();

	std::chrono::high_resolution_clock clock;
	auto start = clock.now();

	for (int i = 0; i < RESET_COUNT; i++) {
		emu.reset_with_mmu(base_mmu);
		emu.state() = base_state;
		emu.set_pc(0x400274);

		emu.run_until(0x400730);
	}

	auto end = clock.now();

	double secs = std::chrono::duration_cast<std::chrono::microseconds>(
			      end - start)
			      .count()
		      / 1000000.0;

	fmt::print("{} resets in {} secs\n", RESET_COUNT, secs);
	fmt::print("{} resets / sec\n", (size_t)(RESET_COUNT / secs));
}
