#include "dyn/emu.hh"
#include "fmt/format.h"
#include "utils/timer.hh"
#include "utils/random.hh"
#include "fuzz/harness.hh"
#include "fuzz/mutator.hh"

#define RESET_COUNT 3000000

class basic_harness : public fuzz::harness
{
      public:
	basic_harness(const elf::elf &bin) : fuzz::harness(bin)
	{
		fuzz_addr_ = bin_.symbol_by_name("dump_elf")->address();
		exit_addr_ = bin_.symbol_by_name("exit")->address();
	}

	virtual void setup(dyn::base_emu &emu) override
	{
		payload_addr_ = emu.alloc_mem(100);
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

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fmt::print("usage: fuzzer binary");
		return 1;
	}

	fuzz::database db;

	fuzz::input base_input(100);
	base_input.data[0] = 0x45;
	db.add(base_input);

	fuzz::mutator mutator(db, 100);

	utils::mapped_file file(argv[1]);
	dyn::emu emu(file, dyn::emu_params(false));

	basic_harness h(emu.bin());

	emu.init();
	h.setup(emu);

	emu.run_until(h.base_state_addr());
	emu.mmu().make_clean_state();
	dyn::mmu base_mmu = emu.mmu();
	dyn::emu_state base_state = emu.state();

	std::unordered_set<uint64_t> bbs;

	{
		TIMERN(reset_timer, "Init corpus run", db.size());

		for (size_t i = 0; i < db.size(); i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(h.base_state_addr());

			h.case_setup(emu,
				     reinterpret_cast<const char *>(
					     db[i].data.data()),
				     db[i].data.size());

			emu.add_on_entry_callback(
				[&](auto pc) { bbs.insert(pc); });

			emu.run_until(h.fuzz_end_addr());

			fmt::print("[{}]: Coverage {}\n", i, bbs.size());
		}
	}

	{
		TIMERN(fuzzing_timer, "Fuzzing", RESET_COUNT);

		for (size_t i = 0; i < RESET_COUNT; i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(h.base_state_addr());

			auto input = mutator.mutate(
				db[utils::rand(0ul, db.size() - 1)]);

			h.case_setup(emu,
				     reinterpret_cast<const char *>(
					     input.data.data()),
				     input.data.size());

			bool added = false;
			emu.add_on_entry_callback([&](auto pc) {
				auto [_, ins] = bbs.insert(pc);
				added |= ins;
			});

			emu.run_until(h.fuzz_end_addr());

			if (added) {
				fmt::print(
					"[{}]: {:#x}{}{}{}{:#x} => Coverage {}\n",
					i, input.data[0], (char)input.data[1],
					(char)input.data[2],
					(char)input.data[3], input.data[4],
					bbs.size());
				db.add(input);
			}
		}
	}

	std::ofstream f("fuzzing_cov.txt");
	for (const auto &v : bbs)
		f << fmt::format("{:#x}\n", v);
}
