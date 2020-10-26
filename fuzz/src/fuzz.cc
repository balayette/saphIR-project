#include <atomic>
#include <chrono>
#include <thread>
#include <signal.h>
#include <getopt.h>

#include "dyn/emu.hh"
#include "fmt/format.h"
#include "utils/timer.hh"
#include "utils/random.hh"
#include "fuzz/harness.hh"
#include "fuzz/mutator.hh"

using std::chrono_literals::operator""s;

bool signal_exit = false;

void sigint_handler(int) { signal_exit = true; }

class basic_harness : public fuzz::harness
{
      public:
	basic_harness(const elf::elf &bin) : fuzz::harness(bin)
	{
		fuzz_addr_ = bin_.symbol_by_name("dump_elf")->address();
		exit_addr_ = bin_.symbol_by_name("exit")->address();

		mutator_.set_max_sz(200);
		fuzz::input base_input(200);
		db_.add(base_input);
	}

	virtual void setup(dyn::base_emu &emu) override
	{
		payload_addr_ = emu.alloc_mem(400);
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

		mutator_.set_max_sz(56);
		fuzz::input base_input(56);
		db_.add(base_input);
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

void fuzz_thread(fuzz::harness *h, utils::mapped_file *file)
{
	dyn::emu emu(*file, dyn::emu_params(false));
	emu.init();

	h->setup(emu);

	emu.run_until(h->base_state_addr());
	emu.mmu().make_base_state();
	dyn::mmu base_mmu = emu.mmu();
	dyn::emu_state base_state = emu.state();

	auto &db = h->db();
	auto &mutator = h->mut();
	auto &stats = h->stat();

	utils::uset<uint64_t> bbs;

	{
		TIMERN(reset_timer, "Init corpus run", db.size());

		for (size_t i = 0; i < db.size(); i++) {
			emu.reset_with_mmu(base_mmu);
			emu.state() = base_state;
			emu.set_pc(h->base_state_addr());

			h->case_setup(emu,
				      reinterpret_cast<const char *>(
					      db[i].data.data()),
				      db[i].data.size());

			emu.add_on_entry_callback([&](auto pc, auto end_pc) {
				for (uint64_t i = pc; i <= end_pc; i += 4) {
					bbs += i;
				}
			});

			emu.run_until(h->fuzz_end_addr());
		}
	}

	h->register_coverage(bbs);

	for (size_t i = 0; !signal_exit; i++) {
		emu.reset_with_mmu(base_mmu);
		emu.state() = base_state;
		emu.set_pc(h->base_state_addr());

		auto input = mutator.mutate(db.pick());

		h->case_setup(emu,
			      reinterpret_cast<const char *>(input.data.data()),
			      input.data.size());

		bool added = false;
		emu.add_on_entry_callback([&](auto pc, auto end_pc) {
			auto [_, ins] = bbs.insert(pc);
			if (!ins)
				return;
			for (uint64_t i = pc + 4; i <= end_pc; i += 4)
				bbs += i;
			added = true;
		});

		emu.run_until(h->fuzz_end_addr());

		if (added)
			db.add(input);

		stats.executed_instrs += emu.instruction_count();
		stats.reset_count++;

		// Don't update the shared state every time
		if (i % 1000 == 0)
			h->register_coverage(bbs);
	}

	h->register_coverage(bbs);
}

struct opts {
	int jobs;
	std::string binary;
	bool help;
};

opts parse_opts(int argc, char **argv)
{
	opts ret{1, "", false};

	int opt;
	while ((opt = getopt(argc, argv, "hj:")) != -1 && !ret.help) {
		if (opt == 'h')
			ret.help = true;
		else if (opt == 'j')
			ret.jobs = std::atoi(optarg);
		else {
			fmt::print("option '{}' not recognized\n", (char)opt);
			ret.help = true;
		}
	}

	if (optind == argc)
		ret.help = true;
	else
		ret.binary = argv[optind];

	return ret;
}

int main(int argc, char *argv[])
{
	auto args = parse_opts(argc, argv);
	if (args.help || args.jobs <= 0) {
		fmt::print("usage: fuzzer binary [-j jobs]");
		return 1;
	}

	utils::mapped_file file(args.binary);
	elf::elf bin(file);

	struct sigaction sa;
	sa.sa_handler = &sigint_handler;
	sigemptyset(&sa.sa_mask);
	ASSERT(sigaction(SIGINT, &sa, NULL) != -1, "sigaction fail");

	microdns_harness h(bin);

	auto &stats = h.stat();
	std::thread stat_thread(
		[](const auto *s) {
			std::this_thread::sleep_for(5s);
			char loop[] = {'|', '/', '-', '\\'};
			for (size_t i = 0; !signal_exit; i++) {
				fmt::print("\r {} {}", loop[i % 4],
					   s->to_string());
				fflush(stdout);
				std::this_thread::sleep_for(0.1s);
			}
		},
		&stats);

	std::vector<std::thread> threads;
	for (int i = 0; i < args.jobs; i++)
		threads.emplace_back(std::thread(fuzz_thread, &h, &file));

	stat_thread.join();
	for (size_t i = 0; i < threads.size(); i++)
		threads[i].join();

	std::ofstream f("fuzzing_cov.txt");
	h.dump_coverage(f);
}
