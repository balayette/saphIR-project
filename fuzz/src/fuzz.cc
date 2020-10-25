#include <atomic>
#include <chrono>
#include <thread>

#include "dyn/emu.hh"
#include "fmt/format.h"
#include "utils/timer.hh"
#include "utils/random.hh"
#include "fuzz/harness.hh"
#include "fuzz/mutator.hh"

#define RESET_COUNT 40000

using std::chrono_literals::operator""s;

struct fuzz_stats {
	fuzz_stats()
	    : start(std::chrono::steady_clock::now()), executed_instrs(0),
	      reset_count(0), coverage(0)
	{
	}

	std::chrono::time_point<std::chrono::steady_clock> start;
	std::atomic<uint64_t> executed_instrs;
	std::atomic<uint64_t> reset_count;
	std::atomic<uint64_t> coverage;

	std::string to_string() const
	{
		uint64_t exe = executed_instrs;
		uint64_t rst = reset_count;

		double s =
			std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - start)
				.count()
			/ 1000000.0;

		uint64_t insn_sec = exe / s;
		uint64_t rst_sec = rst / s;

		return fmt::format(
			"runtime {:.2f} | cov {} | insns {} | insns/sec {} | resets {} | {} resets/sec\n",
			s, coverage, exe, insn_sec, rst, rst_sec);
	}
};

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
		payload_addr_ = emu.alloc_mem(4096);
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

class microdns_harness : public fuzz::harness
{
      public:
	microdns_harness(const elf::elf &bin) : fuzz::harness(bin)
	{
		parse_addr_ = bin_.symbol_by_name("mdns_parse")->address();
		exit_addr_ = bin_.symbol_by_name("exit")->address();
	}

	virtual void setup(dyn::base_emu &emu) override
	{
		payload_addr_ = emu.alloc_mem(500);
		emu.setup();
	}

	virtual uint64_t base_state_addr() const override
	{
		return parse_addr_;
	}

	virtual void case_setup(dyn::base_emu &emu, const char *data,
				size_t sz) override
	{
		emu.mem_write(payload_addr_, data, sz);
		emu.reg_write(mach::aarch64::regs::R2, payload_addr_);
		emu.reg_write(mach::aarch64::regs::R3, sz);
	}

	virtual uint64_t fuzz_end_addr() const override { return exit_addr_; }

      private:
	uint64_t payload_addr_;

	uint64_t parse_addr_;
	uint64_t exit_addr_;
};

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fmt::print("usage: fuzzer binary");
		return 1;
	}

	fuzz::database db;

	fuzz::input base_input(56);
	db.add(base_input);

	uint8_t buf[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
			 0x97, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
			 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00,
			 0x00, 0x00, 0x13, 0x00, 0x79, 0x00, 0x00, 0x01,
			 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	std::memcpy(db[0].data.data(), buf, sizeof(buf));

	fuzz::mutator mutator(db, 56);

	utils::mapped_file file(argv[1]);
	dyn::emu emu(file, dyn::emu_params(false));

	microdns_harness h(emu.bin());

	emu.init();
	h.setup(emu);

	emu.run_until(h.base_state_addr());
	emu.mmu().make_base_state();
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

	fuzz_stats stats;

	std::thread stat_thread(
		[](const auto *s) {
			while (1) {
				fmt::print(s->to_string());
				std::this_thread::sleep_for(1s);
			}
		},
		&stats);

	uint64_t instruction_count = 0;
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
				db.add(input);
				stats.coverage = bbs.size();
			}

			stats.executed_instrs += emu.instruction_count();
			stats.reset_count++;
		}
	}

	fmt::print("Instructions executed: {}\n", instruction_count);

	std::ofstream f("fuzzing_cov.txt");
	for (const auto &v : bbs)
		f << fmt::format("{:#x}\n", v);

	for (size_t i = 0; i < db.size(); i++) {
		std::ofstream inpt_f(fmt::format("output/{}.bin", i));
		inpt_f << db[i].to_string() << '\n';
	}
}
