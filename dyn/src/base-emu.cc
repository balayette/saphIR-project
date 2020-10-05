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

namespace dyn
{
base_emu::base_emu(utils::mapped_file &file, uint64_t brk_addr, uint64_t brk_sz)
    : file_(file), bin_(file), brk_addr_(brk_addr), curr_brk_(brk_addr_),
      brk_sz_(brk_sz), exited_(false)
{
}

void base_emu::setup()
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
	Elf64_auxv_t at_phdr = {
		AT_PHDR,
		{reinterpret_cast<uint64_t>(elf_map_) + bin_.ehdr().phoff()}};
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

	push(0);	// argv end
	push(filename); // program name
	push(1);	// argc
}

void base_emu::align_stack(size_t align)
{
	uint64_t sp = reg_read(mach::aarch64::regs::SP);
	sp = ROUND_DOWN(sp, align);
	reg_write(mach::aarch64::regs::SP, sp);
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

void base_emu::run()
{
	size_t executed = 0;

	std::chrono::high_resolution_clock clock;
	auto start = clock.now();

	size_t bb_count = 0;
	while (!exited_ && bb_count < 1000000) {
		auto [next, exec] = singlestep();
		executed += exec;
		pc_ = next;
	}

	auto end = clock.now();

#if EMU_STATE_LOG
	fmt::print("FINAL STATE\n");
	fmt::print(state_dump());
#endif

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

	ssize_t ret = writev(fd, iov_host, iovcnt);

	delete[] iov_host;

	reg_write(mach::aarch64::regs::R0, ret);
}

void base_emu::syscall()
{
	auto nr = state_.regs[mach::aarch64::regs::R8];
#if EMU_SYSCALL_LOG
	fmt::print("Syscall {:#x}\n", nr);
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
		{ARM64_NR_set_tid_address, &base_emu::sys_set_tid_address},
		{ARM64_NR_ioctl, &base_emu::sys_ioctl},
		{ARM64_NR_writev, &base_emu::sys_writev},
	};

	auto it = syscall_handlers.find(nr);
	ASSERT(it != syscall_handlers.end(), "Unimplemented syscall {}", nr);

	return std::invoke(it->second, this);
}

void base_emu::dispatch_read_cb(uint64_t address, uint64_t size)
{
	uint64_t val = 0;
	mem_read(&val, address, size);

	for (const auto &[f, p] : mem_read_cbs_)
		f(address, size, val, p);
}

void base_emu::dispatch_write_cb(uint64_t address, uint64_t size, uint64_t val)
{
	for (const auto &[f, p] : mem_read_cbs_)
		f(address, size, val, p);
}
} // namespace dyn
