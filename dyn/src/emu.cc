#include "dyn/emu.hh"
#include "arm_syscall_list.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/simplify.hh"
#include "ir/canon/trace.hh"
#include "utils/misc.hh"
#include "backend/graph-regalloc.hh"
#include "backend/linear-regalloc.hh"
#include "utils/bits.hh"
#include "mach/aarch64/aarch64-common.hh"
#include "utils/syscall.hh"

#include <asm/unistd.h>
#include <filesystem>
#include <unistd.h>
#include <sys/types.h>
#include <sys/random.h>
#include <sys/utsname.h>
#include <chrono>

#define EMU_STATE_LOG 0
#define EMU_SYSCALL_LOG 0
#define EMU_ASSEMBLE_LOG 1
#define EMU_COMPILE_LOG 0

#define STACK_SIZE (4096 * 100)

namespace dyn
{
emu::emu(utils::mapped_file &file) : file_(file), bin_(file), exited_(false)
{
	ASSERT(ks_open(KS_ARCH_X86, KS_MODE_64, &ks_) == KS_ERR_OK,
	       "Couldn't init keystone");
	ks_option(ks_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

	std::memset(state_.regs, 0, sizeof(state_.regs));
	state_.nzcv = lifter::Z;
	state_.tpidr_el0 = 0;

	stack_ = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	state_.regs[mach::aarch64::regs::SP] = (size_t)stack_ + STACK_SIZE;

	auto [elf_map, size] = elf::map_elf(bin_, file_);
	elf_map_ = elf_map;
	elf_map_sz_ = size;

	pc_ = bin_.ehdr().entry();
}

emu::~emu()
{
	ks_close(ks_);
	munmap(stack_, STACK_SIZE);

	for (const auto &[_, v] : bb_cache_)
		munmap(v.map, v.size);
}

void emu::push(size_t val) { push(&val, sizeof(size_t)); }

void emu::push(const void *data, size_t sz)
{
	state_.regs[mach::aarch64::regs::SP] -= sz;
	std::memcpy((void *)state_.regs[mach::aarch64::regs::SP], data, sz);
}

void emu::run()
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

	push(0);			     // auxp end
	push(&at_random, sizeof(at_random)); // random data for libc
	push(0);			     // envp end
	push(0);			     // argv end
	push((uint64_t)filename.c_str());    // program name
	push(1);			     // argc

	size_t executed = 0;

	std::chrono::high_resolution_clock clock;
	auto start = clock.now();

	size_t bb_count = 0;
	while (!exited_ && bb_count < 1000000) {
		const auto &chunk = find_or_compile(pc_);
		/* Not printing the message if we exited because of a
		 * comparison to print one message per QEMU chunk and
		 * make debugging easier
		 */
#if EMU_STATE_LOG
		if (state_.exit_reason != lifter::SET_FLAGS)
			fmt::print("Chunk for {:#x} @ {} ({})\n", pc_,
				   chunk.map, chunk.symbol);
		fmt::print(state_dump());
#endif
		bb_fn fn = (bb_fn)(chunk.map);
		executed += chunk.insn_count;
		auto next = fn(&state_);
		switch (state_.exit_reason) {
		case lifter::BB_END:
			break;
		case lifter::SET_FLAGS:
			flag_update();
			break;
		case lifter::SYSCALL:
			syscall();
			break;
		default:
			UNREACHABLE("Unimplemented exit reason {}\n",
				    state_.exit_reason);
		}
		pc_ = next;
#if EMU_STATE_LOG
		fmt::print("Exited basic block.\n");
		fmt::print(state_dump());
#endif
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

void emu::flag_update()
{
	state_.nzcv = 0;

	if (state_.flag_op == lifter::CMP32)
		add_with_carry32(state_.flag_a, ~(uint64_t)state_.flag_b, 1);
	else if (state_.flag_op == lifter::CMP64)
		add_with_carry64(state_.flag_a, ~(uint64_t)state_.flag_b, 1);
	else if (state_.flag_op == lifter::ADDS32)
		add_with_carry32(state_.flag_a, state_.flag_b, 0);
	else if (state_.flag_op == lifter::ADDS64)
		add_with_carry64(state_.flag_a, state_.flag_b, 0);
	else if (state_.flag_op == lifter::ANDS32) {
		uint32_t res = state_.flag_a & state_.flag_b;
		if (res & (1 << 31))
			state_.nzcv |= lifter::N;
		if (res == 0)
			state_.nzcv |= lifter::Z;
	} else if (state_.flag_op == lifter::ANDS64) {
		uint64_t res = state_.flag_a & state_.flag_b;
		if (res & (1ull << 63))
			state_.nzcv |= lifter::N;
		if (res == 0)
			state_.nzcv |= lifter::Z;
	} else
		UNREACHABLE("Unimplemented flag update");
}

void emu::sys_exit()
{
	exited_ = true;
	exit_code_ = state_.regs[mach::aarch64::regs::R0];
}

void emu::sys_getuid() { state_.regs[mach::aarch64::regs::R0] = getuid(); }

void emu::sys_geteuid() { state_.regs[mach::aarch64::regs::R0] = geteuid(); }

void emu::sys_getgid() { state_.regs[mach::aarch64::regs::R0] = getgid(); }

void emu::sys_getegid() { state_.regs[mach::aarch64::regs::R0] = getegid(); }

void emu::sys_readlinkat()
{
	int dirfd = state_.regs[mach::aarch64::regs::R0];
	const char *pathname =
		(const char *)state_.regs[mach::aarch64::regs::R1];
	char *buf = (char *)state_.regs[mach::aarch64::regs::R2];
	size_t bufsiz = state_.regs[mach::aarch64::regs::R3];

	if (!strcmp(pathname, "/proc/self/exe")) {
		auto path =
			std::filesystem::canonical(file_.filename()).string();
		strncpy(buf, path.c_str(), bufsiz);
		state_.regs[mach::aarch64::regs::R0] =
			path.size() <= bufsiz ? path.size() : bufsiz;

	} else
		state_.regs[mach::aarch64::regs::R0] =
			readlinkat(dirfd, pathname, buf, bufsiz);
}

void emu::sys_uname()
{
	struct utsname *buf =
		(struct utsname *)state_.regs[mach::aarch64::regs::R0];
	int ret = uname(buf);
	strcpy(buf->machine, "aarch64");

	state_.regs[mach::aarch64::regs::R0] = ret;
}

void emu::sys_brk()
{
	/* Bypass libc */
	state_.regs[mach::aarch64::regs::R0] =
		utils::syscall(__NR_brk, state_.regs[mach::aarch64::regs::R0]);
}

void emu::syscall()
{
	auto nr = state_.regs[mach::aarch64::regs::R8];
#if EMU_SYSCALL_LOG
	fmt::print("Syscall {:#x}\n", nr);
#endif

	static std::unordered_map<uint64_t, syscall_handler> syscall_handlers{
		{ARM64_NR_exit, &emu::sys_exit},
		{ARM64_NR_getuid, &emu::sys_getuid},
		{ARM64_NR_geteuid, &emu::sys_geteuid},
		{ARM64_NR_getgid, &emu::sys_getgid},
		{ARM64_NR_getegid, &emu::sys_getegid},
		{ARM64_NR_brk, &emu::sys_brk},
		{ARM64_NR_uname, &emu::sys_uname},
		{ARM64_NR_readlinkat, &emu::sys_readlinkat},
	};

	auto it = syscall_handlers.find(nr);
	ASSERT(it != syscall_handlers.end(), "Unimplemented syscall {}", nr);

	return std::invoke(it->second, this);
}

std::string emu::state_dump() const
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

const chunk &emu::find_or_compile(size_t pc)
{
	auto it = bb_cache_.find(pc);
	if (it != bb_cache_.end())
		return it->second;

#if EMU_COMPILE_LOG
	fmt::print("Compiling for {:#x}\n", pc);
#endif

	bb_cache_[pc] = compile(pc);
	return bb_cache_[pc];
}

chunk emu::compile(size_t pc)
{
	const auto *seg = bin_.segment_for_address(pc);
	ASSERT(seg, "No segment for pc");

	auto seg_view = seg->contents(file_) + (pc - seg->vaddr());
	auto bb = disas_.next(seg_view.data(), seg_view.size(), pc);

	auto ff = lifter_.lift(bb);

	auto simplified = ir::simplify(ff.body_);
	auto canon = ir::canon(simplified);
	auto bbs = ir::create_bbs(canon, ff.body_lbl_, ff.epi_lbl_);

	auto traces = ir::create_traces(bbs, ff.body_lbl_);
	auto trace = ir::optimize_traces(traces);
	trace.push_back(lifter_.amd64_target().make_label(ff.epi_lbl_));

	auto generator = lifter_.amd64_target().make_asm_generator();
	generator->codegen(trace);
	auto instrs = generator->output();
	ff.frame_->proc_entry_exit_2(instrs);

	backend::regalloc::linear_alloc(instrs, ff);

	auto ret = assemble(lifter_.amd64_target(), instrs, ff.body_lbl_);
	ret.insn_count = bb.size();
	ret.symbol = bin_.symbolize_func(pc);

	return ret;
}

chunk emu::assemble(mach::target &target, std::vector<assem::rinstr> &instrs,
		    utils::label body_lbl)
{
	std::string text;

	text += fmt::format(
		"\tpush %rbp\n"
		"\tmov %rsp, %rbp\n"
		"\tjmp .L_{}\n",
		body_lbl.get());

	for (auto &i : instrs) {
		if (i->repr().size() == 0)
			continue;
		if (!i.as<assem::label>())
			text += '\t';
		text += i->to_string([&](utils::temp t, unsigned sz) {
			return target.register_repr(t, sz);
		}) + '\n';
	}

	text += fmt::format(
		"\tleave\n"
		"\tret\n");

	uint8_t *out;
	size_t size, count;
	if (ks_asm(ks_, text.c_str(), 0, &out, &size, &count) != KS_ERR_OK) {
		UNREACHABLE("Couldn't assemble: {}",
			    ks_strerror(ks_errno(ks_)));
	}

#if EMU_ASSEMBLE_LOG
	fmt::print(text);
	fmt::print("Assembled to {} instruction ({} bytes)\n", count, size);
#endif

	void *map = mmap(NULL, size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
	ASSERT(map != MAP_FAILED, "Couldn't mmap");
	std::memcpy(map, out, size);
	mprotect(map, size, PROT_READ | PROT_EXEC);

	ks_free(out);
	return {map, size, 0, ""};
}

#define UInt(x) ((__uint128_t)x)
#define SInt(x) ((__int128_t)x)

void emu::add_with_carry32(uint32_t x, uint32_t y, int carry)
{
	uint64_t usum = UInt(x) + UInt(y) + UInt(carry);
	int32_t ssum;
	bool overflow = __builtin_sadd_overflow(SInt(x), SInt(y), &ssum);
	if (!overflow)
		overflow = __builtin_sadd_overflow(ssum, SInt(carry), &ssum);

	uint32_t result = usum;

	if (utils::extract_bit(result, 31))
		state_.nzcv |= lifter::N;
	if (result == 0)
		state_.nzcv |= lifter::Z;
	if (UInt(result) != usum)
		state_.nzcv |= lifter::C;
	if (overflow)
		state_.nzcv |= lifter::V;
}

void emu::add_with_carry64(uint64_t x, uint64_t y, int carry)
{
	__uint128_t usum = UInt(x) + UInt(y) + UInt(carry);
	int64_t ssum;
	bool overflow = __builtin_saddl_overflow(SInt(x), SInt(y), &ssum);
	if (!overflow)
		overflow = __builtin_saddl_overflow(ssum, SInt(carry), &ssum);

	uint64_t result = usum;

	if (utils::extract_bit(result, 63))
		state_.nzcv |= lifter::N;
	if (result == 0)
		state_.nzcv |= lifter::Z;
	if (UInt(result) != usum)
		state_.nzcv |= lifter::C;
	if (overflow)
		state_.nzcv |= lifter::V;
}
} // namespace dyn
