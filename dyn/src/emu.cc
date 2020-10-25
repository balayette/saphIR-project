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
#define EMU_ASSEMBLE_LOG 0
#define EMU_COMPILE_LOG 0

extern char **environ;

namespace dyn
{
emu::emu(utils::mapped_file &file, const emu_params &p)
    : base_emu(file, p), disas_(p.singlestep), mmu_(p.mmap_addr, 20000000)
{
	ASSERT(ks_open(KS_ARCH_X86, KS_MODE_64, &ks_) == KS_ERR_OK,
	       "Couldn't init keystone");
	ks_option(ks_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

	state_.emu = this;
	state_.store_fun = [](auto *emu, auto addr, auto val, auto sz) {
		auto *t = static_cast<dyn::emu *>(emu);
		t->handle_store(addr, val, sz);
	};
	state_.load_fun = [](auto *emu, auto addr, auto sz) {
		auto *t = static_cast<dyn::emu *>(emu);
		return t->handle_load(addr, sz);
	};
}

emu::~emu()
{
	ks_close(ks_);

	for (const auto &[_, v] : bb_cache_)
		munmap(v.map, v.size);
}

void emu::handle_store(uint64_t addr, uint64_t val, size_t sz)
{
	ASSERT(sz == 1 || sz == 2 || sz == 4 || sz == 8, "Wrong load size");

	dispatch_write_cb(addr, sz, val);

	ASSERT(mmu_.write(addr, &val, sz) == mmu_status::OK,
	       "Invalid memory write");
}

uint64_t emu::handle_load(uint64_t addr, size_t sz)
{
	ASSERT(sz == 1 || sz == 2 || sz == 4 || sz == 8, "Wrong load size");

	uint64_t val;
	ASSERT(mmu_.read(&val, addr, sz) == mmu_status::OK,
	       "Invalid memory read");

	dispatch_read_cb(addr, sz, val);
	return val;
}

void emu::reset_with_mmu(const dyn::mmu &base)
{
	exited_ = false;
	icount_ = 0;

	std::memset(state_.regs, 0, sizeof(state_.regs));
	state_.nzcv = lifter::Z;
	state_.tpidr_el0 = 0;

	state_.regs[mach::aarch64::regs::SP] = stack_addr_ + stack_sz_;
	curr_brk_ = brk_addr_;

	mmap_offt_ = mmap_base_ + base.size();

	pc_ = bin_.ehdr().entry();

	on_entry_cbs_.clear();

	mmu_.reset(base);
}

std::pair<uint64_t, size_t> emu::singlestep()
{
	if (state_.exit_reason != lifter::SET_FLAGS)
		dispatch_on_entry(pc_);

	const auto &chunk = find_or_compile(pc_);
	/* Not printing the message if we exited because of a
	 * comparison to print one message per QEMU chunk and
	 * make debugging easier
	 */
#if EMU_STATE_LOG
	if (state_.exit_reason != lifter::SET_FLAGS)
		fmt::print("Chunk for {:#x} @ {} ({})\n", pc_, chunk.map,
			   chunk.symbol);
	fmt::print(state_dump());
#endif
	bb_fn fn = (bb_fn)(chunk.map);
	auto next = fn(&state_, &mmu_);
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

#if EMU_STATE_LOG
	fmt::print("Exited basic block.\n");
	fmt::print(state_dump());
#endif

	return std::make_pair(next, chunk.insn_count);
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

uint64_t emu::alloc_mem(size_t length)
{
	auto ret = mmu_.mmap(0, length);
	ASSERT(std::holds_alternative<vaddr_t>(ret), "allocation failed");

	return std::get<vaddr_t>(ret);
}

void emu::mem_map(uint64_t guest_addr, size_t length, int prot, int flags,
		  int fd, off_t offset)
{
	auto ret = mmu_.mmap(guest_addr, length, prot, flags, fd, offset);
	ASSERT(std::holds_alternative<vaddr_t>(ret), "mmap failed");
}

void emu::mem_write(uint64_t guest_addr, const void *src, size_t sz)
{
	ASSERT(mmu_.write(guest_addr, src, sz) == mmu_status::OK,
	       "Mem write failed");
}

void emu::mem_read(void *dst, uint64_t guest_addr, size_t sz)
{
	ASSERT(mmu_.read(dst, guest_addr, sz) == mmu_status::OK,
	       "Mem read failed");
}

void emu::sys_mmap()
{
	uint64_t addr = reg_read(mach::aarch64::regs::R0);
	size_t len = (size_t)reg_read(mach::aarch64::regs::R1);
	int prot = (int)reg_read(mach::aarch64::regs::R2);
	int flags = (int)reg_read(mach::aarch64::regs::R3);
	int fildes = (int)reg_read(mach::aarch64::regs::R4);
	off_t off = (off_t)reg_read(mach::aarch64::regs::R5);

	auto ret = mmu_.mmap(addr, len, prot, flags, fildes, off);

	if (std::holds_alternative<vaddr_t>(ret))
		reg_write(mach::aarch64::regs::R0, std::get<vaddr_t>(ret));
	else
		reg_write(mach::aarch64::regs::R0, -1);
}

void emu::sys_munmap()
{
	uint64_t addr = reg_read(mach::aarch64::regs::R0);
	size_t len = (size_t)reg_read(mach::aarch64::regs::R1);

	auto ret = mmu_.munmap(addr, len);

	ASSERT(ret == mmu_status::OK, "munmap failed");
	reg_write(mach::aarch64::regs::R0, 0);
}

void emu::sys_mprotect()
{
	uint64_t addr = reg_read(mach::aarch64::regs::R0);
	size_t len = (size_t)reg_read(mach::aarch64::regs::R1);
	int prot = (int)reg_read(mach::aarch64::regs::R2);

	auto ret = mmu_.mprotect(addr, len, prot);

	ASSERT(ret == mmu_status::OK, "mprotect failed");
	reg_write(mach::aarch64::regs::R0, 0);
}

const chunk &emu::find_or_compile(size_t pc)
{
	auto it = bb_cache_.find(pc);
	if (it != bb_cache_.end())
		return it->second;

#if EMU_COMPILE_LOG
	fmt::print("Compiling for {:#x} ({})\n", pc, bin_.symbolize_func(pc));
#endif

	bb_cache_[pc] = compile(pc);
	return bb_cache_[pc];
}

chunk emu::compile(size_t pc)
{
	const auto *seg = bin_.segment_for_address(pc);
	ASSERT(seg, "No segment for pc {:#x}", pc);

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
	ff.frame_->add_live_registers(instrs);

	backend::regalloc::graph_alloc(instrs, ff);

	auto f =
		ff.frame_->make_asm_function(instrs, ff.body_lbl_, ff.epi_lbl_);

	auto ret = assemble(lifter_.amd64_target(), f);
	ret.insn_count = bb.size();
	ret.symbol = bin_.symbolize_func(pc);

	return ret;
}

chunk emu::assemble(mach::target &target, mach::asm_function &f)
{
	std::string text;

	text += f.prologue_;

	for (auto &i : f.instrs_) {
		if (i->repr().size() == 0)
			continue;
		if (!i.as<assem::label>())
			text += '\t';
		text += i->to_string([&](utils::temp t, unsigned sz) {
			return target.register_repr(t, sz);
		}) + '\n';
	}

	text += f.epilogue_;
	text += "\n";

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
	bool overflow =
		__builtin_sadd_overflow(SInt(x), SInt(y) + UInt(carry), &ssum);

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
	bool overflow =
		__builtin_saddl_overflow(SInt(x), SInt(y) + UInt(carry), &ssum);

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
