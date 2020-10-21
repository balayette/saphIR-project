#include "dyn/emu.hh"
#include "fmt/format.h"
#include "utils/timer.hh"
#include "utils/random.hh"

#define RESET_COUNT 3000000

struct corpus {
	void add(uint64_t val) { corpus.push_back(val); }
	uint64_t choose_random() const
	{
		return *utils::choose(corpus.begin(), corpus.end());
	}

	size_t size() const { return corpus.size(); }

	std::vector<uint64_t> corpus;
};

uint64_t mutate(uint64_t val)
{
	switch (utils::rand(0, 7)) {
	case 0:
		return val + utils::rand(0, 1000);
	case 1:
		return val - utils::rand(0, 1000);
	case 3:
		return val * utils::rand(0, 1000);
	case 5:
		return val >> utils::rand(0, 32);
	case 6:
		return val << utils::rand(0, 32);
	case 7:
		return val / utils::rand(1, 10);
	default:
		return mutate(mutate(val));
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fmt::print("usage: fuzzer binary");
		return 1;
	}

	utils::mapped_file file(argv[1]);
	dyn::emu emu(file, dyn::emu_params(false));

	auto main_addr = emu.bin().symbol_by_name("main")->address();
	auto other_addr = emu.bin().symbol_by_name("fuzz")->address();

	corpus corp;
	corp.add(0);
	corp.add(1);
	corp.add(2);
	corp.add(1000);

	emu.init();

	uint64_t payload_addr = emu.alloc_mem(sizeof(uint64_t));
	emu.setup({payload_addr});

	emu.run_until(main_addr);

	emu.mmu().make_clean_state();
	dyn::mmu base_mmu = emu.mmu();
	lifter::state base_state = emu.state();

	std::unordered_set<uint64_t> bbs;

	{
		TIMERN(reset_timer, "Init corpus run", corp.size());

		for (size_t i = 0; i < corp.size(); i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(main_addr);

			emu.mem_write(payload_addr, &corp.corpus[i],
				      sizeof(uint64_t));
			emu.run_until(other_addr);

			emu.add_on_entry_callback(
				[&](auto pc) { bbs.insert(pc); });

			emu.run_until(0x40030c);

			fmt::print("{:#018x} => Coverage {}\n", corp.corpus[i],
				   bbs.size());
		}
	}

	{
		TIMERN(fuzzing_timer, "Fuzzing", RESET_COUNT);

		for (size_t i = 0; i < RESET_COUNT; i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(main_addr);

			uint64_t v = mutate(corp.choose_random());
			emu.mem_write(payload_addr, &v, sizeof(uint64_t));
			emu.run_until(other_addr);

			bool added = false;
			emu.add_on_entry_callback([&](auto pc) {
				auto [_, ins] = bbs.insert(pc);
				added |= ins;
			});

			emu.run_until(0x40030c);

			if (added) {
				fmt::print("{:#018x} => Coverage {}\n", v,
					   bbs.size());
				corp.add(v);
			}
		}
	}

	std::ofstream f("fuzzing_cov.txt");
	for (const auto &v : bbs)
		f << fmt::format("{:#x}\n", v);
}
