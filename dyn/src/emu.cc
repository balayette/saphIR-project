#include "dyn/emu.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/trace.hh"
#include "utils/misc.hh"
#include "backend/regalloc.hh"
#include "mach/aarch64/aarch64-common.hh"

#include <asm/unistd.h>
#include <unistd.h>
#include <sys/types.h>
#include <chrono>

namespace dyn
{
static inline int64_t syscall1(uint64_t syscall_nr, uint64_t arg1)
{
	int64_t ret;

	asm volatile("syscall\n"
		     : "=a"(ret)
		     : "a"(syscall_nr), "D"(arg1)
		     : "memory", "rcx", "r11");

	return ret;
}

emu::emu(utils::mapped_file &file) : file_(file), bin_(file)
{
	ASSERT(ks_open(KS_ARCH_X86, KS_MODE_64, &ks_) == KS_ERR_OK,
	       "Couldn't init keystone");
	ks_option(ks_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	std::memset(state_.regs, 0, sizeof(state_.regs));

	stack_ = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	state_.regs[mach::aarch64::regs::SP] = (size_t)stack_ + 4096;
	state_.nzcv = lifter::Z;
	state_.tpidr_el0 = 0;

	auto [elf_map, size] = elf::map_elf(bin_, file_);
	elf_map_ = elf_map;
	elf_map_sz_ = size;

	pc_ = bin_.ehdr().entry();
}

emu::~emu()
{
	ks_close(ks_);
	munmap(stack_, 4096);

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

	push(0);
	push(0);
	push(0);
	push(filename.c_str(), filename.size() + 1);
	push(1);

	size_t executed = 0;

	std::chrono::high_resolution_clock clock;
	auto start = clock.now();

	int done = -1;
	size_t bb_count = 0;
	while (done < 0 && bb_count < 1000000) {
		const auto &chunk = find_or_compile(pc_);
		fmt::print("Chunk for {:#x} @ {}\n", pc_, chunk.map);
		bb_fn fn = (bb_fn)(chunk.map);
		fmt::print(state_dump());
		executed += chunk.insn_count;
		pc_ = fn(&state_);
		switch (state_.exit_reason) {
		case lifter::BB_END:
			break;
		case lifter::SET_FLAGS:
			flag_update();
			break;
		case lifter::SYSCALL:
			done = syscall();
			break;
		default:
			UNREACHABLE("Unimplemented exit reason");
		}
		fmt::print("Exited basic block.\n");
		fmt::print(state_dump());
	}

	auto end = clock.now();

	fmt::print("FINAL STATE\n");
	fmt::print(state_dump());
	double secs = std::chrono::duration_cast<std::chrono::microseconds>(
			      end - start)
			      .count()
		      / 1000000.0;
	fmt::print("Executed {} instructions in {} secs\n", executed, secs);
	fmt::print("{} instructions / sec\n", (size_t)(executed / secs));
	if (done >= 0)
		fmt::print("Program exited with status code {}\n", done);
	else
		fmt::print("Program exited after reaching exec limit\n");
}

void emu::flag_update()
{
	fmt::print("CMP {:#x} {:#x}\n", state_.flag_a, state_.flag_b);
	state_.nzcv = 0;

	if (state_.flag_op == lifter::CMP32)
		add_with_carry(32, state_.flag_a, ~(uint64_t)state_.flag_b, 1);
	else if (state_.flag_op == lifter::CMP64)
		add_with_carry(64, state_.flag_a, ~(uint64_t)state_.flag_b, 1);
	else if (state_.flag_op == lifter::ADDS32)
		add_with_carry(32, state_.flag_a, state_.flag_b, 0);
	else if (state_.flag_op == lifter::ADDS64)
		add_with_carry(64, state_.flag_a, state_.flag_b, 0);
	else if (state_.flag_op == lifter::ANDS32) {
		uint32_t res = state_.flag_a & state_.flag_b;
		if (res & (1 << 31))
			state_.nzcv |= lifter::N;
		if (res == 0)
			state_.nzcv |= lifter::Z;
	} else
		UNREACHABLE("Unimplemented flag update");
}

int emu::syscall()
{
	fmt::print("Syscall {:#x}\n", state_.regs[mach::aarch64::regs::R8]);
	switch (state_.regs[mach::aarch64::regs::R8]) {
	case 0x5d:
		return state_.regs[mach::aarch64::regs::R0];
	case 0xae:
		state_.regs[mach::aarch64::regs::R0] = getuid();
		break;
	case 0xaf:
		state_.regs[mach::aarch64::regs::R0] = geteuid();
		break;
	case 0xb0:
		state_.regs[mach::aarch64::regs::R0] = getgid();
		break;
	case 0xb1:
		state_.regs[mach::aarch64::regs::R0] = getegid();
		break;
	case 0xd6:
		state_.regs[mach::aarch64::regs::R0] = syscall1(
			__NR_brk, state_.regs[mach::aarch64::regs::R0]);
		break;
	default:
		UNREACHABLE("Unimplemented syscall wrapper");
	}

	return -1;
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

	fmt::print("Compiling for {:#x}\n", pc);
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

	auto canon = ir::canon(ff.body_);
	auto bbs = ir::create_bbs(canon, ff.body_lbl_, ff.epi_lbl_);

	auto traces = ir::create_traces(bbs, ff.body_lbl_);
	auto trace = ir::optimize_traces(traces);
	trace.push_back(lifter_.amd64_target().make_label(ff.epi_lbl_));

	auto generator = lifter_.amd64_target().make_asm_generator();
	generator->codegen(trace);
	auto instrs = generator->output();
	ff.frame_->proc_entry_exit_2(instrs);

	backend::regalloc::alloc(instrs, ff);

	auto ret = assemble(lifter_.amd64_target(), instrs, ff.body_lbl_);
	ret.insn_count = bb.size();

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

	fmt::print(text);

	uint8_t *out;
	size_t size, count;
	if (ks_asm(ks_, text.c_str(), 0, &out, &size, &count) != KS_ERR_OK) {
		fmt::print("{}\n", ks_strerror(ks_errno(ks_)));
		UNREACHABLE("Couldn't assemble");
	}

	fmt::print("Assembled to {} instruction ({} bytes)\n", count, size);

	void *map = mmap(NULL, size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
	ASSERT(map != MAP_FAILED, "Couldn't mmap");
	std::memcpy(map, out, size);
	mprotect(map, size, PROT_READ | PROT_EXEC);

	ks_free(out);
	return {map, size, 0};
}

#define UInt(x) ((__uint128_t)x)
#define SInt(x) ((__int128_t)x)

static inline uint64_t Bits64(const uint64_t bits, const uint32_t msbit,
			      const uint32_t lsbit)
{
	return (bits >> lsbit) & ((1ull << (msbit - lsbit + 1)) - 1);
}

static inline uint64_t Bit64(const uint64_t bits, const uint32_t bit)
{
	return (bits >> bit) & 1ull;
}

void emu::add_with_carry(size_t N, uint64_t x, uint64_t y, int carry)
{
	fmt::print("add_with_carry({}, {:#x}, {:#x}, {})\n", N, x, y, carry);
	__uint128_t usum = UInt(x) + UInt(y) + UInt(carry);
	int64_t ssum;
	bool overflow = __builtin_saddl_overflow(SInt(x), SInt(y), &ssum);
	if (!overflow)
		overflow = __builtin_saddl_overflow(ssum, SInt(carry), &ssum);

	uint64_t result = usum;
	if (N < 64)
		result = Bits64(result, N - 1, 0);

	if (Bit64(result, N - 1))
		state_.nzcv |= lifter::N;
	if (result == 0)
		state_.nzcv |= lifter::Z;
	if (UInt(result) != usum)
		state_.nzcv |= lifter::C;
	if (overflow)
		state_.nzcv |= lifter::V;
}
} // namespace dyn
