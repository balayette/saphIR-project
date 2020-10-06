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
	emu(utils::mapped_file &file, bool singlestep,
	    uint64_t stack_addr = DEFAULT_STACK_ADDR,
	    uint64_t stack_sz = DEFAULT_STACK_SIZE,
	    uint64_t brk_addr = DEFAULT_BRK_ADDR,
	    uint64_t brk_sz = DEFAULT_BRK_SIZE);
	virtual ~emu();

	std::pair<uint64_t, size_t> singlestep() override;

	void add_mem_read_callback(mem_read_callback cb, void *data) override;
	void add_mem_write_callback(mem_write_callback cb, void *data) override;

	void mem_map(uint64_t guest_addr, size_t length, int prot, int flags,
		     int fd = -1, off_t offset = 0) override;
	void mem_write(uint64_t guest_addr, const void *src,
		       size_t sz) override;
	void mem_read(void *dst, uint64_t guest_addr, size_t sz) override;

      private:
	using bb_fn = size_t (*)(lifter::state *);

	const chunk &find_or_compile(size_t pc);
	chunk compile(size_t pc);
	chunk assemble(mach::target &target, mach::asm_function &f);

	void add_with_carry32(uint32_t x, uint32_t y, int carry);
	void add_with_carry64(uint64_t x, uint64_t y, int carry);

	void flag_update();

	ks_engine *ks_;

	lifter::lifter lifter_;
	lifter::disas disas_;

	void *stack_;
	size_t stack_sz_;
	size_t elf_map_sz_;

	std::unordered_map<size_t, chunk> bb_cache_;
};
} // namespace dyn
