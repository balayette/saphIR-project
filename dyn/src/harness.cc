#include "utils/fs.hh"
#include "dyn/emu.hh"
#include "dyn/unicorn-emu.hh"

template <typename T> static void dump_mem(const std::vector<T> &v)
{
	for (const auto &p : v)
		fmt::print("{}\n", p.to_string());
}

struct mem_write_payload {
	uint64_t addr;
	uint64_t size;
	uint64_t val;

	bool operator==(const mem_write_payload &other) const
	{
		return addr == other.addr && size == other.size
		       && val == other.val;
	}

	bool operator!=(const mem_write_payload &other) const
	{
		return !(*this == other);
	}

	std::string to_string() const
	{
		return fmt::format("MEM WRITE{} {:#018x} @ {:#018x}", size, val,
				   addr);
	}
};

struct mem_read_payload {
	uint64_t addr;
	uint64_t size;
	uint64_t val;

	bool operator==(const mem_read_payload &other) const
	{
		return addr == other.addr && size == other.size
		       && val == other.val;
	}

	bool operator!=(const mem_read_payload &other) const
	{
		return !(*this == other);
	}

	std::string to_string() const
	{
		return fmt::format("MEM READ{} {:#018x} @ {:#018x}", size, val,
				   addr);
	}
};

std::vector<mem_read_payload> ref_rd, emu_rd;
std::vector<mem_write_payload> ref_wr, emu_wr;

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

	if (ref_rd.size() != emu_rd.size()) {
		fmt::print("Different number of reads\n");
		fmt::print("Reference reads:\n");
		dump_mem(ref_rd);
		fmt::print("Emu reads:\n");
		dump_mem(emu_rd);
		difference = true;
	} else {
		for (size_t i = 0; i < ref_rd.size(); i++) {
			auto r = ref_rd[i];
			auto e = emu_rd[i];

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

	dyn::emu_params p(true);

	dyn::unicorn_emu ref_emu(file, p);
	dyn::emu emu(file, p);
	ASSERT(!state_divergence(ref_emu, emu), "State divergence at creation");

	ref_emu.add_mem_read_callback(
		[](uint64_t address, uint64_t size, uint64_t val, void *) {
			ref_rd.push_back({address, size, val});
		},
		nullptr);
	emu.add_mem_read_callback(
		[](uint64_t address, uint64_t size, uint64_t val, void *) {
			emu_rd.push_back({address, size, val});
		},
		nullptr);
	ref_emu.add_mem_write_callback(
		[](uint64_t address, uint64_t size, uint64_t val, void *) {
			ref_wr.push_back({address, size, val});
		},
		nullptr);
	emu.add_mem_write_callback(
		[](uint64_t address, uint64_t size, uint64_t val, void *) {
			emu_wr.push_back({address, size, val});
		},
		nullptr);

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
				"State divergence after {} instructions @ {:#x}! Next instruction: {:#x}\n",
				i, curr_pc, ref_pc);
			fmt::print("Reference state:\n");
			fmt::print(ref_emu.state_dump());
			fmt::print("Emulator state:\n");
			fmt::print(emu.state_dump());
			break;
		}

		if (emu.exited() || ref_emu.exited()) {
			ASSERT(emu.exited() == ref_emu.exited(),
			       "Both did not exit");
			ASSERT(emu.exit_code() == ref_emu.exit_code(),
			       "Exited with different exit codes");
			fmt::print("Exited with code {}\n",
				   ref_emu.exit_code());
			break;
		}

		ref_rd.clear();
		emu_rd.clear();
		ref_wr.clear();
		emu_wr.clear();
	}
}
