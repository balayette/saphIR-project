#include "utils/fs.hh"
#include "dyn/emu.hh"
#include "dyn/unicorn-emu.hh"

template <typename T> static void dump_mem(const std::vector<T> &v)
{
	for (const auto &p : v)
		fmt::print("{}\n", p.to_string());
}

bool state_divergence(const dyn::base_emu &ref, const dyn::base_emu &emu)
{
	bool difference = false;

	if (ref.pc() != emu.pc()) {
		fmt::print("PC different : Expected {:#x}, got {:#x}\n",
			   ref.pc(), emu.pc());
		difference = true;
	}

	const auto &ref_state = ref.state();
	const auto &emu_state = emu.state();

	for (size_t i = 0; i < 32; i++) {
		if (ref_state.regs[i] != emu_state.regs[i]) {
			fmt::print(
				"r{} different : Expected {:#x}, got {:#x}\n",
				i, ref_state.regs[i], emu_state.regs[i]);
			difference = true;
		}
	}

	if (ref_state.tpidr_el0 != emu_state.tpidr_el0) {
		fmt::print("TLS different : Expected {:#x}, got {:#x}\n",
			   ref_state.tpidr_el0, emu_state.tpidr_el0);
		difference = true;
	}

	if (ref_state.nzcv != emu_state.nzcv) {
		fmt::print("NZCV different : Expected {:#x}, got {:#x}\n",
			   ref_state.nzcv, emu_state.nzcv);
		difference = true;
	}

	const auto &ref_wr = ref.mem_writes();
	const auto &emu_wr = emu.mem_writes();

	if (ref_wr.size() != emu_wr.size()) {
		fmt::print("Different number of writes\n");
		fmt::print("Reference writes:\n");
		dump_mem(ref_wr);
		fmt::print("Emu writes:\n");
		dump_mem(emu_wr);
		difference = true;
	} else {
		for (size_t i = 0; i < ref_wr.size(); i++) {
			auto r = ref_wr[i];
			auto e = emu_wr[i];

			if (r != e) {
				fmt::print("Different write:\n");
				fmt::print("  Expected {}\n", r.to_string());
				fmt::print("  Got      {}\n", e.to_string());
				difference = true;
			}
		}
	}

	const auto &ref_re = ref.mem_reads();
	const auto &emu_re = emu.mem_reads();

	if (ref_re.size() != emu_re.size()) {
		fmt::print("Different number of reads\n");
		fmt::print("Reference reads:\n");
		dump_mem(ref_re);
		fmt::print("Emu reads:\n");
		dump_mem(emu_re);
		difference = true;
	} else {
		for (size_t i = 0; i < ref_re.size(); i++) {
			auto r = ref_re[i];
			auto e = emu_re[i];

			if (r != e) {
				fmt::print("Different read:\n");
				fmt::print("  Expected {}\n", r.to_string());
				fmt::print("  Got      {}\n", e.to_string());
				difference = true;
			}
		}
	}

	return difference;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		std::cerr << "usage: dyn binary\n";
		return 1;
	}

	utils::mapped_file file(argv[1]);

	dyn::unicorn_emu ref_emu(file);
	dyn::emu emu(file, true);
	ASSERT(!state_divergence(ref_emu, emu), "State divergence at creation");

	ref_emu.setup();
	emu.setup();
	ASSERT(!state_divergence(ref_emu, emu), "State divergence at setup");

	for (int i = 0; i < 10000000; i++) {
		auto curr_pc = ref_emu.pc();

		auto [emu_pc, _] = emu.singlestep();
		auto [ref_pc, __] = ref_emu.singlestep();

		emu.set_pc(emu_pc);
		ref_emu.set_pc(ref_pc);

		if (!state_divergence(ref_emu, emu))
			fmt::print("{:#018x} - OK\n", curr_pc);
		else {
			fmt::print(
				"State divergence after {:#x}! Next instruction: {:#x}\n",
				curr_pc, ref_pc);
			fmt::print("Reference state:\n");
			fmt::print(ref_emu.state_dump());
			fmt::print("Emulator state:\n");
			fmt::print(emu.state_dump());
			break;
		}

		if (emu.exited() || ref_emu.exited()) {
			fmt::print("Exited\n");
			break;
		}

		emu.clear_mem_writes();
		ref_emu.clear_mem_writes();

		emu.clear_mem_reads();
		ref_emu.clear_mem_reads();
	}
}
