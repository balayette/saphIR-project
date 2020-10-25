#pragma once

#include <atomic>
#include <chrono>
#include <mutex>

#include "dyn/base-emu.hh"
#include "utils/uset.hh"
#include "fuzz/mutator.hh"

namespace fuzz
{
struct stats {
	stats()
	    : start(std::chrono::steady_clock::now()), executed_instrs(0),
	      reset_count(0), coverage(0)
	{
	}

	std::chrono::time_point<std::chrono::steady_clock> start;
	std::atomic<uint64_t> executed_instrs;
	std::atomic<uint64_t> reset_count;
	std::atomic<uint64_t> coverage;
	std::atomic<uint64_t> db_size;

	std::string to_string() const
	{
		uint64_t exe = executed_instrs;
		uint64_t rst = reset_count;
		uint64_t db_sz = db_size;

		double s =
			std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - start)
				.count()
			/ 1000000.0;

		uint64_t insn_sec = exe / s;
		uint64_t rst_sec = rst / s;

		return fmt::format(
			"runtime {:.2f} | cov {} | insns {} | insns/sec {} | resets {} | {} resets/sec | db size {}",
			s, coverage, exe, insn_sec, rst, rst_sec, db_sz);
	}
};

class harness
{
      public:
	harness(const elf::elf &bin) : bin_(bin), mutator_(db_) {}
	virtual ~harness() = default;

	/*
	 * One time setup
	 */
	virtual void setup(dyn::base_emu &emu);

	/*
	 * The fuzzer will run the program until this address is reached after
	 * setup, and then save the state.
	 * This address will be the starting point of fuzzing cases.
	 */
	virtual uint64_t base_state_addr() const = 0;

	/*
	 * Setup the input for the run, could also use run_until() if coverage
	 * should start after base_state_addr()
	 */
	virtual void case_setup(dyn::base_emu &emu, const char *data,
				size_t sz) = 0;

	/*
	 * Run until this address is reached
	 */
	virtual uint64_t fuzz_end_addr() const = 0;

	database &db() { return db_; }
	mutator &mut() { return mutator_; }
	stats &stat() { return stats_; }

	void register_coverage(const utils::uset<uint64_t> &bbs)
	{
		std::scoped_lock lock(bb_mutex_);

		bbs_ += bbs;
		stats_.coverage = bbs_.size();
		stats_.db_size = db_.size();
	}

	void dump_coverage(std::ofstream &f)
	{
		std::scoped_lock lock(bb_mutex_);

		for (const auto &v : bbs_)
			f << fmt::format("{:#x}\n", v);
	}

      protected:
	const elf::elf &bin_;

	database db_;
	mutator mutator_;
	stats stats_;

	std::mutex bb_mutex_;
	utils::uset<uint64_t> bbs_;
};
} // namespace fuzz
