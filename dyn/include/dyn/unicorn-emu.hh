#pragma once

#include "dyn/base-emu.hh"
#include "unicorn/unicorn.h"

namespace dyn
{
class unicorn_emu : public base_emu
{
      public:
	unicorn_emu(utils::mapped_file &file, const emu_params &p);
	virtual ~unicorn_emu() = default;

	std::pair<uint64_t, size_t> singlestep() override;

	void add_mem_read_callback(mem_read_callback cb, void *data) override;
	void add_mem_write_callback(mem_write_callback cb, void *data) override;

	void mem_map(uint64_t guest_addr, size_t length, int prot, int flags,
		     int fd = -1, off_t offset = 0) override;
	void mem_write(uint64_t guest_addr, const void *src,
		       size_t sz) override;
	void mem_read(void *dst, uint64_t guest_addr, size_t sz) override;

	void reg_write(mach::aarch64::regs r, uint64_t val) override;

      protected:
	void *map_elf();

	void ureg_write(int reg, uint64_t val);
	uint64_t ureg_read(int reg);

	/*
	 * We need to maintain the lifter::state and unicorn state in sync
	 * When modifying state_, update the unicorn state with state_to_unicorn
	 * and when modifying unicorn state, update state_ with unicorn_to_state
	 */
	void unicorn_to_state();
	void state_to_unicorn();

	uc_engine *uc_;

      private:
	uc_hook mem_read_hdl_;
	uc_hook mem_write_hdl_;
};
} // namespace dyn
