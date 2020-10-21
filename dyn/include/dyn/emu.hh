#pragma once
#include "lifter/lifter.hh"
#include "lifter/disas.hh"
#include "utils/fs.hh"
#include "elf/elf.hh"
#include "dyn/base-emu.hh"
#include "dyn/mmu.hh"
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
	emu(utils::mapped_file &file, const emu_params &p);
	virtual ~emu();

	std::pair<uint64_t, size_t> singlestep() override;

	void mem_map(uint64_t guest_addr, size_t length, int prot, int flags,
		     int fd = -1, off_t offset = 0) override;
	void mem_write(uint64_t guest_addr, const void *src,
		       size_t sz) override;
	void mem_read(void *dst, uint64_t guest_addr, size_t sz) override;

	const dyn::mmu &mmu() const { return mmu_; }

	void reset_with_mmu(const dyn::mmu &base);

      private:
	using bb_fn = size_t (*)(lifter::state *, dyn::mmu *mmu);

	void handle_store(uint64_t addr, uint64_t val, size_t sz);
	uint64_t handle_load(uint64_t addr, size_t sz);

	const chunk &find_or_compile(size_t pc);
	chunk compile(size_t pc);
	chunk assemble(mach::target &target, mach::asm_function &f);

	void add_with_carry32(uint32_t x, uint32_t y, int carry);
	void add_with_carry64(uint64_t x, uint64_t y, int carry);

	void flag_update();

	ks_engine *ks_;

	lifter::lifter lifter_;
	lifter::disas disas_;
	dyn::mmu mmu_;

	std::unordered_map<size_t, chunk> bb_cache_;
};
} // namespace dyn
