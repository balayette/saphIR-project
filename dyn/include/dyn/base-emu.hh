#pragma once

#include "utils/fs.hh"
#include "elf/elf.hh"
#include "lifter/lifter.hh"

namespace dyn
{
class base_emu
{
      public:
	base_emu(utils::mapped_file &file);
	virtual ~base_emu() = default;

	void setup();
	virtual std::pair<uint64_t, size_t> singlestep() = 0;
	virtual void run();

	lifter::state &state() { return state_; }
	const lifter::state &state() const { return state_; }
	std::string state_dump() const;

	size_t pc() const { return pc_; }
	void set_pc(size_t pc) { pc_ = pc; }

      protected:
	virtual void align_stack(size_t align) = 0;
	virtual uint64_t push(size_t val) = 0;
	virtual uint64_t push(const void *data, size_t sz) = 0;

	utils::mapped_file &file_;
	elf::elf bin_;

	void *elf_map_;

	lifter::state state_;
	size_t pc_;

	bool exited_;
	int exit_code_;
};
} // namespace dyn
