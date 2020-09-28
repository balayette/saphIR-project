#include "dyn/base-emu.hh"
#include "lifter/lifter.hh"
#include <chrono>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

namespace dyn
{
base_emu::base_emu(utils::mapped_file &file)
    : file_(file), bin_(file), exited_(false)
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

	const auto &filename = file_.filename();
	char random_data[16];
	getrandom(random_data, sizeof(random_data), 0);
	Elf64_auxv_t at_random = {AT_RANDOM, {(uint64_t)random_data}};
	Elf64_auxv_t at_pagesz = {AT_PAGESZ, {4096}};
	Elf64_auxv_t at_hwcap = {AT_HWCAP, {0xecfffffb}};
	Elf64_auxv_t at_clktck = {
		AT_CLKTCK, {static_cast<uint64_t>(sysconf(_SC_CLK_TCK))}};
	Elf64_auxv_t at_phdr = {
		AT_PHDR,
		{reinterpret_cast<uint64_t>(elf_map_) + bin_.ehdr().phoff()}};
	fmt::print("at_phdr: {:#x}\n", at_phdr.a_un.a_val);
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
	for (char **env = environ; *env; env++)
		push((uint64_t)*env);

	push(0);			  // argv end
	push((uint64_t)filename.c_str()); // program name
	push(1);			  // argc
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
} // namespace dyn
