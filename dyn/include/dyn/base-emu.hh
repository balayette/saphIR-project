#pragma once

#include <fstream>

#include "utils/fs.hh"
#include "elf/elf.hh"
#include "lifter/lifter.hh"
#include "mach/aarch64/aarch64-common.hh"

#define DEFAULT_STACK_ADDR 0x7331BEEF0000
#define DEFAULT_STACK_SIZE (0x1000 * 100)
#define DEFAULT_BRK_ADDR 0x1337DEAD0000
#define DEFAULT_BRK_SIZE (0x1000 * 100)
#define DEFAULT_MMAP_ADDR 0xDEADBEEF0000

namespace dyn
{
struct emu_params {
	emu_params(bool singlestep = false,
		   std::optional<std::string> coverage = std::nullopt,
		   uint64_t stack_addr = DEFAULT_STACK_ADDR,
		   uint64_t stack_sz = DEFAULT_STACK_SIZE,
		   uint64_t brk_addr = DEFAULT_BRK_ADDR,
		   uint64_t brk_sz = DEFAULT_BRK_SIZE,
		   uint64_t mmap_addr = DEFAULT_MMAP_ADDR)
	    : singlestep(singlestep), coverage(coverage),
	      stack_addr(stack_addr), stack_sz(stack_sz), brk_addr(brk_addr),
	      brk_sz(brk_sz), mmap_addr(mmap_addr)
	{
	}

	bool singlestep;
	std::optional<std::string> coverage;

	uint64_t stack_addr;
	uint64_t stack_sz;

	uint64_t brk_addr;
	uint64_t brk_sz;

	uint64_t mmap_addr;
};

class base_emu
{
      public:
	using mem_write_callback = void (*)(uint64_t addr, uint64_t size,
					    uint64_t val, void *user_data);
	using mem_read_callback = void (*)(uint64_t addr, uint64_t size,
					   uint64_t val, void *user_data);

	base_emu(utils::mapped_file &file, const emu_params &p);
	virtual ~base_emu() = default;

	void setup();
	virtual std::pair<uint64_t, size_t> singlestep() = 0;
	virtual void run();

	lifter::state &state() { return state_; }
	const lifter::state &state() const { return state_; }
	std::string state_dump() const;

	size_t pc() const { return pc_; }
	void set_pc(size_t pc) { pc_ = pc; }

	bool exited() const { return exited_; }
	int exit_code() const { return exit_code_; }

	virtual void add_mem_read_callback(mem_read_callback cb,
					   void *data) = 0;
	virtual void add_mem_write_callback(mem_write_callback cb,
					    void *data) = 0;

	virtual void reg_write(mach::aarch64::regs r, uint64_t val);
	virtual uint64_t reg_read(mach::aarch64::regs r);

	virtual void mem_write(uint64_t guest_addr, const void *src,
			       size_t sz) = 0;
	virtual void mem_read(void *dst, uint64_t guest_addr, size_t sz) = 0;

	virtual void align_stack(size_t align);
	virtual uint64_t push(size_t val);
	virtual uint64_t push(const void *data, size_t sz);

	virtual void mem_map(uint64_t guest_addr, size_t length, int prot,
			     int flags, int fd = -1, off_t offset = 0) = 0;
	virtual std::string string_read(uint64_t guest_addr);

	/*
	 * If you are using this, you better know what you are doing.
	 */
	void dispatch_read_cb(uint64_t address, uint64_t size);
	void dispatch_write_cb(uint64_t address, uint64_t size, uint64_t val);

      protected:
	using syscall_handler = void (base_emu::*)(void);

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
	void sys_set_tid_address();
	void sys_ioctl();
	void sys_writev();

	utils::mapped_file &file_;
	elf::elf bin_;

	void *elf_map_;

	uint64_t brk_addr_;
	uint64_t curr_brk_;
	size_t brk_sz_;

	uint64_t mmap_offt_;

	lifter::state state_;
	size_t pc_;

	bool exited_;
	int exit_code_;

	std::vector<std::pair<mem_read_callback, void *>> mem_read_cbs_;
	std::vector<std::pair<mem_write_callback, void *>> mem_write_cbs_;

	/*
	 * Should be called after executing an instructions / basic block,
	 * handles coverage.
	 */
	virtual void coverage_hook(uint64_t pc);

	bool coverage_;
	std::ofstream coverage_file_;
};
} // namespace dyn
