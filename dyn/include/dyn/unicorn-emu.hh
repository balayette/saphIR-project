#pragma once

#include "dyn/base-emu.hh"
#include "unicorn/unicorn.h"

namespace dyn
{
class unicorn_emu : public base_emu
{
      public:
	unicorn_emu(utils::mapped_file &file, uint64_t stack_addr,
		    uint64_t stack_sz);
	virtual ~unicorn_emu() = default;

	std::pair<uint64_t, size_t> singlestep() override;

      private:
	void align_stack(size_t align) override;
	void *map_elf();

	uint64_t push(size_t val) override;
	uint64_t push(const void *data, size_t sz) override;

	void mem_write(size_t addr, const void *data, size_t sz);
	uint64_t reg_read(int reg);
	void reg_write(int reg, uint64_t val);

	void update_state();

	uc_engine *uc_;
};
} // namespace dyn
