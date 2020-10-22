#include "dyn/emu.hh"
#include "fmt/format.h"
#include "utils/timer.hh"
#include "utils/random.hh"
#include "fuzz/harness.hh"

#define RESET_COUNT 3000000

class basic_harness : public fuzz::harness
{
      public:
	basic_harness(const elf::elf &bin) : fuzz::harness(bin)
	{
		fuzz_addr_ = bin_.symbol_by_name("fuzz")->address();
		exit_addr_ = bin_.symbol_by_name("exit")->address();
	}

	virtual void setup(dyn::base_emu &emu) override
	{
		payload_addr_ = emu.alloc_mem(sizeof(uint64_t));
		emu.setup({payload_addr_});
	}

	virtual uint64_t base_state_addr() const override { return fuzz_addr_; }

	virtual void case_setup(dyn::base_emu &emu, const char *data,
				size_t sz) override
	{
		emu.mem_write(payload_addr_, data, sz);
	}

	virtual uint64_t fuzz_end_addr() const override { return exit_addr_; }

      private:
	uint64_t payload_addr_;

	uint64_t fuzz_addr_;
	uint64_t exit_addr_;
};

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

	corpus corp;
	corp.add(0);
	corp.add(1);
	corp.add(2);

	basic_harness h(emu.bin());

	emu.init();
	h.setup(emu);

	emu.run_until(h.base_state_addr());
	emu.mmu().make_clean_state();
	dyn::mmu base_mmu = emu.mmu();
	lifter::state base_state = emu.state();

	std::unordered_set<uint64_t> bbs;

	{
		TIMERN(reset_timer, "Init corpus run", corp.size());

		for (size_t i = 0; i < corp.size(); i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(h.base_state_addr());

			h.case_setup(emu,
				     reinterpret_cast<const char *>(
					     corp.corpus.data() + i),
				     sizeof(uint64_t));

			emu.add_on_entry_callback(
				[&](auto pc) { bbs.insert(pc); });

			emu.run_until(h.fuzz_end_addr());

			fmt::print("{:#018x} => Coverage {}\n", corp.corpus[i],
				   bbs.size());
		}
	}

	{
		TIMERN(fuzzing_timer, "Fuzzing", RESET_COUNT);

		for (size_t i = 0; i < RESET_COUNT; i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(h.base_state_addr());

			uint64_t v = mutate(corp.choose_random());
			h.case_setup(emu, reinterpret_cast<const char *>(&v),
				     sizeof(uint64_t));

			bool added = false;
			emu.add_on_entry_callback([&](auto pc) {
				auto [_, ins] = bbs.insert(pc);
				added |= ins;
			});

			emu.run_until(h.fuzz_end_addr());

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
