#include "dyn/emu.hh"
#include "fmt/format.h"
#include "utils/timer.hh"

#define RESET_COUNT 1000000

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

	{
		TIMERN(reset_timer, "Reset Bench", RESET_COUNT);

		for (int i = 0; i < RESET_COUNT; i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(0x400274);

			emu.run_until(0x400730);
		}
	}
}
