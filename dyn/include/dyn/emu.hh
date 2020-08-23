#pragma once
#include "lifter/lifter.hh"
#include "lifter/disas.hh"
#include "utils/fs.hh"
#include "elf/elf.hh"
#include "keystone/keystone.h"
#include <unordered_map>

namespace dyn
{
struct chunk {
	void *map;
	size_t size;
	size_t insn_count;
};

class emu
{
      public:
	emu(utils::mapped_file &file);
	~emu();
	void run();
	lifter::state &state() { return state_; }
	std::string state_dump() const;

      private:
	using bb_fn = size_t (*)(lifter::state *);

	void push(size_t val);
	void push(const void *data, size_t sz);

	const chunk &find_or_compile(size_t pc);
	chunk compile(size_t pc);
	chunk assemble(mach::target &target, std::vector<assem::rinstr> &instrs,
		       utils::label body_lbl);

	void add_with_carry32(uint32_t x, uint32_t y, int carry);
	void add_with_carry64(uint64_t x, uint64_t y, int carry);

	void flag_update();
	int syscall();
	void emu_uname();
	void emu_readlinkat();

	utils::mapped_file &file_;
	elf::elf bin_;
	ks_engine *ks_;

	lifter::lifter lifter_;
	lifter::disas disas_;

	void *stack_;
	lifter::state state_;
	size_t pc_;
	void *elf_map_;
	size_t elf_map_sz_;

	std::unordered_map<size_t, chunk> bb_cache_;
};
} // namespace dyn
