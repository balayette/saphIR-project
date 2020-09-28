#pragma once
#include "lifter/lifter.hh"
#include "lifter/disas.hh"
#include "utils/fs.hh"
#include "elf/elf.hh"
#include "dyn/base-emu.hh"
#include "keystone/keystone.h"
#include <unordered_map>

namespace dyn
{
struct chunk {
	void *map;
	size_t size;
	size_t insn_count;

	std::string symbol;
};

class emu : public base_emu
{
      public:
	emu(utils::mapped_file &file, bool singlestep = false);
	virtual ~emu();

	std::pair<uint64_t, size_t> singlestep() override;

      private:
	using bb_fn = size_t (*)(lifter::state *);
	using syscall_handler = void (emu::*)(void);

	void align_stack(size_t align) override;
	uint64_t push(size_t val) override;
	uint64_t push(const void *data, size_t sz) override;

	const chunk &find_or_compile(size_t pc);
	chunk compile(size_t pc);
	chunk assemble(mach::target &target, std::vector<assem::rinstr> &instrs,
		       utils::label body_lbl);

	void add_with_carry32(uint32_t x, uint32_t y, int carry);
	void add_with_carry64(uint64_t x, uint64_t y, int carry);

	void flag_update();

	/* Syscalls */
	void syscall();
	void sys_exit();
	void sys_getuid();
	void sys_geteuid();
	void sys_getgid();
	void sys_getegid();
	void sys_brk();
	void sys_uname();
	void sys_readlinkat();
	void sys_mmap();

	ks_engine *ks_;

	lifter::lifter lifter_;
	lifter::disas disas_;

	void *stack_;
	size_t elf_map_sz_;

	std::unordered_map<size_t, chunk> bb_cache_;
};
} // namespace dyn
