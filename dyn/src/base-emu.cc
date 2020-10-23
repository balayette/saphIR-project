#include "dyn/base-emu.hh"
#include "arm_syscall_list.hh"
#include "lifter/lifter.hh"
#include "utils/misc.hh"
#include "utils/syscall.hh"
#include <chrono>
#include <filesystem>
#include <sys/utsname.h>
#include <asm/unistd.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

extern char **environ;

#define EMU_SYSCALL_LOG 0
#define EMU_VERBOSE 0

namespace dyn
{
base_emu::base_emu(utils::mapped_file &file, const emu_params &p)
    : file_(file), bin_(file), stack_addr_(p.stack_addr), stack_sz_(p.stack_sz),
      brk_addr_(p.brk_addr), curr_brk_(p.brk_addr), brk_sz_(p.brk_sz),
      mmap_base_(p.mmap_addr), mmap_offt_(p.mmap_addr), exited_(false)
{
}

void base_emu::init()
{
	elf_map_ = map_elf();

	mem_map(stack_addr_, stack_sz_, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

	mem_map(brk_addr_, brk_sz_, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

	reset();
}

void base_emu::reset()
{
	exited_ = false;

	std::memset(state_.regs, 0, sizeof(state_.regs));
	state_.nzcv = lifter::Z;
	state_.tpidr_el0 = 0;

	mem_set(stack_addr_, 0, stack_sz_);
	state_.regs[mach::aarch64::regs::SP] = stack_addr_ + stack_sz_;

	mem_set(brk_addr_, 0, brk_sz_);
	curr_brk_ = brk_addr_;

	mmap_offt_ = mmap_base_;

	pc_ = bin_.ehdr().entry();

	on_entry_cbs_.clear();
}

void base_emu::setup(const std::vector<uint64_t> &args)
{
	/*
	 * The stack frame at the entry point is as follows
	 * 0 auxp
	 * 0 envp
	 * 0 end of argv
	 * arg 2
	 * arg 1
	 * program name
	 * argc <-- sp
	 */

	uint64_t filename =
		push(file_.filename().c_str(), file_.filename().size() + 1);
	std::vector<uint64_t> envs;
	for (char **env = environ; *env; env++) {
		envs.push_back(push(*env, strlen(*env) + 1));
	}
	align_stack(16);

	uint64_t random_data[2] = {0xdeadbeefbeefdead, 0x1337177337717337};
	uint64_t rand_addr = push(random_data, sizeof(random_data));
	Elf64_auxv_t at_random = {AT_RANDOM, {rand_addr}};
	Elf64_auxv_t at_pagesz = {AT_PAGESZ, {4096}};
	Elf64_auxv_t at_hwcap = {AT_HWCAP, {0}};
	Elf64_auxv_t at_clktck = {
		AT_CLKTCK, {static_cast<uint64_t>(sysconf(_SC_CLK_TCK))}};
	Elf64_auxv_t at_phdr = {AT_PHDR, {elf_map_ + bin_.ehdr().phoff()}};
	Elf64_auxv_t at_phent = {AT_PHENT, {sizeof(Elf64_Phdr)}};
	Elf64_auxv_t at_phnum = {AT_PHNUM, {bin_.phdrs().size()}};

	Elf64_auxv_t at_uid = {AT_UID, {getuid()}};
	Elf64_auxv_t at_euid = {AT_EUID, {geteuid()}};
	Elf64_auxv_t at_gid = {AT_GID, {getgid()}};
	Elf64_auxv_t at_egid = {AT_EGID, {getegid()}};

	Elf64_auxv_t at_end = {AT_NULL, {0}};

	/*
	 * Push the auxv in the same order as QEMU, to make it easier to diff
	 * the execution traces
	 */
	push(&at_end, sizeof(Elf64_auxv_t));	// auxp end
	push(&at_random, sizeof(Elf64_auxv_t)); // random data for libc
	push(&at_clktck, sizeof(Elf64_auxv_t));
	push(&at_hwcap, sizeof(Elf64_auxv_t));
	push(&at_egid, sizeof(Elf64_auxv_t));
	push(&at_gid, sizeof(Elf64_auxv_t));
	push(&at_euid, sizeof(Elf64_auxv_t));
	push(&at_uid, sizeof(Elf64_auxv_t));
	push(&at_pagesz, sizeof(Elf64_auxv_t));
	push(&at_phnum, sizeof(Elf64_auxv_t));
	push(&at_phent, sizeof(Elf64_auxv_t));
	push(&at_phdr, sizeof(Elf64_auxv_t));

	push(0); // envp end
	for (const auto &e : envs)
		push(e);

	push(0); // argv end
	for (auto it = args.crbegin(); it != args.crend(); ++it)
		push(*it);

	push(filename);	       // program name
	push(1 + args.size()); // argc
}

void base_emu::align_stack(size_t align)
{
	uint64_t sp = reg_read(mach::aarch64::regs::SP);
	sp = ROUND_DOWN(sp, align);
	reg_write(mach::aarch64::regs::SP, sp);
}

uint64_t base_emu::alloc_mem(size_t length)
{
	uint64_t addr = mmap_offt_;
	mmap_offt_ += ROUND_UP(length, 4096);

	mem_map(addr, ROUND_UP(length, 4096), PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS);

	return addr;
}

uint64_t base_emu::push(size_t val) { return push(&val, sizeof(val)); }

uint64_t base_emu::push(const void *data, size_t sz)
{
	uint64_t sp = reg_read(mach::aarch64::regs::SP);
	sp -= sz;

	mem_write(sp, data, sz);
	reg_write(mach::aarch64::regs::SP, sp);

	return sp;
}

void base_emu::mem_set(uint64_t guest_addr, int val, size_t sz)
{
	for (size_t i = 0; i < sz; i++)
		mem_write(guest_addr + i, &val, 1);
}

void base_emu::reg_write(mach::aarch64::regs r, uint64_t val)
{
	state_.regs[r] = val;
}

uint64_t base_emu::reg_read(mach::aarch64::regs r) { return state_.regs[r]; }

std::string base_emu::string_read(uint64_t guest_addr)
{
	std::string ret;
	char c;
	mem_read(&c, guest_addr, sizeof(c));

	for (size_t i = 1; c; i++) {
		ret.append(1, c);
		mem_read(&c, guest_addr + i, sizeof(c));
	}

	return ret;
}

void base_emu::run_until(uint64_t addr)
{
	while (!exited_) {
		auto [next, _] = singlestep();
		pc_ = next;
		if (pc_ == addr)
			return;
	}
}

void base_emu::run()
{
	size_t executed = 0;

#if EMU_VERBOSE
	std::chrono::high_resolution_clock clock;
	auto start = clock.now();
#endif

	size_t bb_count = 0;
	while (!exited_ && bb_count < 1000000) {
		auto [next, exec] = singlestep();
		executed += exec;
		pc_ = next;
	}

#if EMU_VERBOSE
	auto end = clock.now();
#endif

#if EMU_STATE_LOG
	fmt::print("FINAL STATE\n");
	fmt::print(state_dump());
#endif

#if EMU_VERBOSE
	double secs = std::chrono::duration_cast<std::chrono::microseconds>(
			      end - start)
			      .count()
		      / 1000000.0;
	fmt::print("Executed {} instructions in {} secs\n", executed, secs);
	fmt::print("{} instructions / sec\n", (size_t)(executed / secs));
	if (exited_)
		fmt::print("Program exited with status code {}\n", exit_code_);
	else
		fmt::print("Program exited after reaching exec limit\n");
#endif
}

std::string base_emu::state_dump() const
{
	std::string repr;

	repr += fmt::format("pc  : {:#018x} ", pc_);
	int line_count = 1;

	for (size_t i = 0; i < 32; i++) {
		repr += fmt::format("r{:02} : {:#018x} ", i, state_.regs[i]);
		if (++line_count % 3 == 0)
			repr += '\n';
	}

	repr += fmt::format("nzcv: {}{}{}{}\n",
			    state_.nzcv & lifter::N ? 'N' : 'n',
			    state_.nzcv & lifter::Z ? 'Z' : 'z',
			    state_.nzcv & lifter::C ? 'C' : 'c',
			    state_.nzcv & lifter::V ? 'V' : 'v');
	repr += fmt::format("TLS: {:#x}\n", state_.tpidr_el0);

	return repr;
}

void base_emu::sys_exit()
{
	exited_ = true;
	exit_code_ = reg_read(mach::aarch64::regs::R0);
}

void base_emu::sys_getuid() { reg_write(mach::aarch64::regs::R0, getuid()); }

void base_emu::sys_geteuid() { reg_write(mach::aarch64::regs::R0, geteuid()); }

void base_emu::sys_getgid() { reg_write(mach::aarch64::regs::R0, getgid()); }

void base_emu::sys_getegid() { reg_write(mach::aarch64::regs::R0, getegid()); }

void base_emu::sys_readlinkat()
{
	int dirfd = reg_read(mach::aarch64::regs::R0);
	auto pathname = string_read(reg_read(mach::aarch64::regs::R1));
	auto buf = reg_read(mach::aarch64::regs::R2);
	size_t bufsiz = reg_read(mach::aarch64::regs::R3);

	if (!strcmp(pathname.c_str(), "/proc/self/exe")) {
		auto path =
			std::filesystem::canonical(file_.filename()).string();
		mem_write(buf, path.c_str(), bufsiz);
		reg_write(mach::aarch64::regs::R0,
			  path.size() <= bufsiz ? path.size() : bufsiz);
	} else {
		char temp_buf[4096] = {0};
		ssize_t ret =
			readlinkat(dirfd, pathname.c_str(), temp_buf, bufsiz);

		mem_write(buf, temp_buf, ret);
		reg_write(mach::aarch64::regs::R0, ret);
	}
}

void base_emu::sys_uname()
{
	struct utsname buf;
	uint64_t buf_addr = reg_read(mach::aarch64::regs::R0);
	mem_read(&buf, buf_addr, sizeof(buf));

	int ret = uname(&buf);
	strcpy(buf.machine, "aarch64");

	mem_write(buf_addr, &buf, sizeof(buf));
	reg_write(mach::aarch64::regs::R0, ret);
}

void base_emu::sys_brk()
{
	uint64_t new_addr = reg_read(mach::aarch64::regs::R0);
	if (new_addr > brk_addr_ && new_addr < brk_addr_ + brk_sz_)
		curr_brk_ = new_addr;

	reg_write(mach::aarch64::regs::R0, curr_brk_);
}

void base_emu::sys_mmap()
{
	uint64_t addr = reg_read(mach::aarch64::regs::R0);
	size_t len = (size_t)reg_read(mach::aarch64::regs::R1);
	int prot = (int)reg_read(mach::aarch64::regs::R2);
	int flags = (int)reg_read(mach::aarch64::regs::R3);
	int fildes = (int)reg_read(mach::aarch64::regs::R4);
	off_t off = (off_t)reg_read(mach::aarch64::regs::R5);

	if (flags & MAP_FIXED) {
		reg_write(mach::aarch64::regs::R0, addr);
		mem_map(addr, len, prot, flags, fildes, off);
		return;
	}

	addr = mmap_offt_;
	mmap_offt_ += ROUND_UP(len, 4096);
	reg_write(mach::aarch64::regs::R0, addr);
	mem_map(addr, len, prot, flags, fildes, off);
}

void base_emu::sys_set_tid_address()
{
	/*
	 * We should be fine with a no-op here.
	 */
}

void base_emu::sys_ioctl()
{
	/*
	 * We should be fine with a no-op here.
	 */
}

void base_emu::sys_writev()
{
	int fd = reg_read(mach::aarch64::regs::R0);
	uint64_t iov = reg_read(mach::aarch64::regs::R1);
	int iovcnt = reg_read(mach::aarch64::regs::R2);

	auto iov_host = new struct iovec[iovcnt];
	mem_read(iov_host, iov, iovcnt * sizeof(struct iovec));

	for (int i = 0; i < iovcnt; i++) {
		auto new_base = new char[iov_host[i].iov_len];
		mem_read(new_base,
			 reinterpret_cast<uint64_t>(iov_host[i].iov_base),
			 iov_host[i].iov_len);

		iov_host[i].iov_base = new_base;
	}

	ssize_t ret = writev(fd, iov_host, iovcnt);

	for (int i = 0; i < iovcnt; i++)
		delete[] static_cast<char *>(iov_host[i].iov_base);
	delete[] iov_host;

	reg_write(mach::aarch64::regs::R0, ret);
}

void base_emu::sys_munmap() { reg_write(mach::aarch64::regs::R0, 0); }

void base_emu::sys_mprotect() { reg_write(mach::aarch64::regs::R0, 0); }

void base_emu::syscall()
{
	auto nr = state_.regs[mach::aarch64::regs::R8];
#if EMU_SYSCALL_LOG
	fmt::print("Syscall {}\n", nr);
#endif

	static std::unordered_map<uint64_t, syscall_handler> syscall_handlers{
		{ARM64_NR_exit, &base_emu::sys_exit},
		{ARM64_NR_exit_group, &base_emu::sys_exit},
		{ARM64_NR_getuid, &base_emu::sys_getuid},
		{ARM64_NR_geteuid, &base_emu::sys_geteuid},
		{ARM64_NR_getgid, &base_emu::sys_getgid},
		{ARM64_NR_getegid, &base_emu::sys_getegid},
		{ARM64_NR_brk, &base_emu::sys_brk},
		{ARM64_NR_uname, &base_emu::sys_uname},
		{ARM64_NR_readlinkat, &base_emu::sys_readlinkat},
		{ARM64_NR_mmap, &base_emu::sys_mmap},
		{ARM64_NR_munmap, &base_emu::sys_munmap},
		{ARM64_NR_mprotect, &base_emu::sys_mprotect},
		{ARM64_NR_set_tid_address, &base_emu::sys_set_tid_address},
		{ARM64_NR_ioctl, &base_emu::sys_ioctl},
		{ARM64_NR_writev, &base_emu::sys_writev},
	};

	auto it = syscall_handlers.find(nr);
	ASSERT(it != syscall_handlers.end(), "Unimplemented syscall {}", nr);

	return std::invoke(it->second, this);
}

void base_emu::dispatch_read_cb(uint64_t address, uint64_t size, uint64_t val)
{
	for (const auto &[f, p] : mem_read_cbs_)
		f(address, size, val, p);
}

void base_emu::dispatch_write_cb(uint64_t address, uint64_t size, uint64_t val)
{
	for (const auto &[f, p] : mem_write_cbs_)
		f(address, size, val, p);
}

void base_emu::add_mem_read_callback(mem_read_callback cb, void *data)
{
	mem_read_cbs_.push_back({cb, data});
}

void base_emu::add_mem_write_callback(mem_write_callback cb, void *data)
{
	mem_write_cbs_.push_back({cb, data});
}

void base_emu::add_on_entry_callback(std::function<void(uint64_t)> f)
{
	on_entry_cbs_.push_back(f);
}

void base_emu::dispatch_on_entry(uint64_t pc)
{
	for (const auto &f : on_entry_cbs_)
		f(pc);
}

uint64_t base_emu::map_elf()
{
	size_t min = ~0;
	size_t max = 0;

	for (const auto &segment : bin_.phdrs()) {
		if (segment.type() != PT_LOAD)
			continue;
		if (segment.vaddr() < min)
			min = segment.vaddr();
		if (segment.vaddr() + segment.memsz() > max)
			max = segment.vaddr() + segment.memsz();
	}

	min = ROUND_DOWN(min, 4096);
	max = ROUND_UP(max, 4096);
	size_t size = max - min;
	size_t map = min;

	mem_map(min, size, PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS);

	for (const auto &segment : bin_.phdrs()) {
		if (segment.type() != PT_LOAD)
			continue;

		auto contents = segment.contents(file_).data();

		mem_write(map + (segment.vaddr() - min), contents,
			  segment.filesz());
	}

	return map;
}
} // namespace dyn
