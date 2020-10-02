#pragma once

#include "utils/fs.hh"
#include "elf/elf.hh"
#include "lifter/lifter.hh"
#include "mach/aarch64/aarch64-common.hh"

#define DEFAULT_STACK_ADDR 0xBEEF0000
#define DEFAULT_STACK_SIZE (0x1000 * 100)
#define DEFAULT_BRK_ADDR 0xDEAD0000
#define DEFAULT_BRK_SIZE (0x1000 * 100)

namespace dyn
{
class base_emu
{
      public:
	base_emu(utils::mapped_file &file, uint64_t brk_addr = DEFAULT_BRK_ADDR,
		 uint64_t brk_sz = DEFAULT_BRK_SIZE);
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
	using syscall_handler = void (base_emu::*)(void);

	virtual void align_stack(size_t align);
	virtual uint64_t push(size_t val);
	virtual uint64_t push(const void *data, size_t sz);

	virtual void reg_write(mach::aarch64::regs r, uint64_t val);
	virtual uint64_t reg_read(mach::aarch64::regs r);

	virtual void mem_write(uint64_t guest_addr, const void *src,
			       size_t sz) = 0;
	virtual void mem_read(void *dst, uint64_t guest_addr, size_t sz) = 0;
	virtual std::string string_read(uint64_t guest_addr);

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

	utils::mapped_file &file_;
	elf::elf bin_;

	void *elf_map_;

	uint64_t brk_addr_;
	uint64_t curr_brk_;
	size_t brk_sz_;

	lifter::state state_;
	size_t pc_;

	bool exited_;
	int exit_code_;
};
} // namespace dyn
