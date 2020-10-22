#pragma once

#include "dyn/base-emu.hh"

namespace fuzz
{
class harness
{
      public:
	harness(const elf::elf &bin) : bin_(bin) {}
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

      protected:
	const elf::elf &bin_;
};
} // namespace fuzz
