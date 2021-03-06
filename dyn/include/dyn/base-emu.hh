#pragma once

#include <fstream>

#include "utils/fs.hh"
#include "elf/elf.hh"
#include "lifter/lifter.hh"
#include "mach/aarch64/aarch64-common.hh"

#define DEFAULT_STACK_ADDR 0x7331BEEF0000ull
#define DEFAULT_STACK_SIZE (0x4000)
#define DEFAULT_BRK_ADDR 0x1337DEAD0000ull
#define DEFAULT_BRK_SIZE (0x1000 * 100)
#define DEFAULT_MMAP_ADDR 0xDEADBEEF0000ull

namespace dyn
{
struct emu_state {
	uint64_t regs[32];
	uint64_t nzcv;
	uint64_t flag_a;
	uint64_t flag_b;
	uint64_t flag_op;
	uint64_t exit_reason;
	uint64_t tpidr_el0;

	/*
	 * store_fun(emu, addr, val, sz)
	 * load_fun(emu, addr, sz);
	 */
	void *emu;
	lifter::store_fun_fn store_fun;
	lifter::load_fun_fn load_fun;

	uint64_t mmu_error;
	uint64_t fault_address;
	uint64_t fault_pc;
};

struct emu_params {
	emu_params(bool singlestep = false,
		   uint64_t stack_addr = DEFAULT_STACK_ADDR,
		   uint64_t stack_sz = DEFAULT_STACK_SIZE,
		   uint64_t brk_addr = DEFAULT_BRK_ADDR,
		   uint64_t brk_sz = DEFAULT_BRK_SIZE,
		   uint64_t mmap_addr = DEFAULT_MMAP_ADDR)
	    : singlestep(singlestep), stack_addr(stack_addr),
	      stack_sz(stack_sz), brk_addr(brk_addr), brk_sz(brk_sz),
	      mmap_addr(mmap_addr)
	{
	}

	bool singlestep;

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
	using on_entry_callback =
		std::function<void(uint64_t pc, uint64_t end_pc)>;

	base_emu(utils::mapped_file &file, const emu_params &p);
	virtual ~base_emu() = default;

	/*
	 * Bare minimum initialization of the emulator
	 * - Map the stack
	 * - Map the brk
	 * - Map the binary
	 */
	void init();
	/*
	 * Reset the emulator state
	 * - Zeroes the stack (does not unmap it)
	 * - Zeroes the brk and resets curr_brk_ (does not unmap it)
	 * - Unmaps all mapped pages
	 * - Resets the registers, sets pc to the entry point
	 *
	 * XXX: does not close all file descriptors created by open(), because
	 * we simply forward syscalls.
	 */
	virtual void reset();
	void setup(const std::vector<uint64_t> &args = {});

	virtual std::pair<uint64_t, size_t> singlestep() = 0;
	virtual void run();

	/*
	 * The address should be a basic block boundary if not single stepping
	 */
	bool run_until(uint64_t addr);

	emu_state &state() { return state_; }
	const emu_state &state() const { return state_; }
	std::string state_dump() const;

	size_t pc() const { return pc_; }
	void set_pc(size_t pc) { pc_ = pc; }

	bool exited() const { return exited_; }
	int exit_code() const { return exit_code_; }

	virtual void add_mem_read_callback(mem_read_callback cb, void *data);
	virtual void add_mem_write_callback(mem_write_callback cb, void *data);
	void add_on_entry_callback(on_entry_callback f);

	virtual void reg_write(mach::aarch64::regs r, uint64_t val);
	virtual uint64_t reg_read(mach::aarch64::regs r);

	virtual void mem_write(uint64_t guest_addr, const void *src,
			       size_t sz) = 0;
	virtual void mem_read(void *dst, uint64_t guest_addr, size_t sz) = 0;
	virtual void mem_set(uint64_t guest_addr, int val, size_t sz);

	virtual void align_stack(size_t align);
	virtual uint64_t push(size_t val);
	virtual uint64_t push(const void *data, size_t sz);

	virtual void mem_map(uint64_t guest_addr, size_t length, int prot,
			     int flags, int fd = -1, off_t offset = 0) = 0;
	virtual uint64_t alloc_mem(size_t length);
	virtual std::string string_read(uint64_t guest_addr);

	/*
	 * If you are using this, you better know what you are doing.
	 */
	void dispatch_read_cb(uint64_t address, uint64_t size, uint64_t val);
	void dispatch_write_cb(uint64_t address, uint64_t size, uint64_t val);

	const elf::elf &bin() const { return bin_; }

	uint64_t instruction_count() const { return icount_; }

      protected:
	using syscall_handler = void (base_emu::*)(void);

	uint64_t map_elf();

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
	virtual void sys_mmap();
	virtual void sys_munmap();
	virtual void sys_mprotect();
	void sys_set_tid_address();
	void sys_ioctl();
	void sys_writev();

	utils::mapped_file &file_;
	elf::elf bin_;

	uint64_t elf_map_;

	uint64_t stack_addr_;
	uint64_t stack_sz_;

	uint64_t brk_addr_;
	uint64_t curr_brk_;
	size_t brk_sz_;

	uint64_t mmap_base_;
	uint64_t mmap_offt_;

	emu_state state_;
	size_t pc_;

	bool exited_;
	int exit_code_;

	uint64_t icount_;

	std::vector<std::pair<mem_read_callback, void *>> mem_read_cbs_;
	std::vector<std::pair<mem_write_callback, void *>> mem_write_cbs_;

	std::vector<on_entry_callback> on_entry_cbs_;

	/*
	 * Should be called before executing an instruction / basic block
	 */
	void dispatch_on_entry(uint64_t pc, uint64_t end_pc);
};
} // namespace dyn
