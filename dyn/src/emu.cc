#include "dyn/emu.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/trace.hh"
#include "backend/regalloc.hh"

namespace dyn
{
emu::emu(utils::mapped_file &file) : file_(file), bin_(file)
{
	ASSERT(ks_open(KS_ARCH_X86, KS_MODE_64, &ks_) == KS_ERR_OK,
	       "Couldn't init keystone");
	ks_option(ks_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	std::memset(state_.regs, 0, sizeof(state_.regs));

	pc_ = bin_.ehdr().entry();
}

emu::~emu()
{
	ks_close(ks_);
	for (const auto &[_, v] : bb_cache_)
		munmap(v.map, v.size);
}

void emu::run()
{
	while (true) {
		const auto &chunk = find_or_compile(pc_);
		fmt::print("Chunk for {:#x} @ {}\n", pc_, chunk.map);

		fmt::print(state_dump());
		bb_fn fn = (bb_fn)(chunk.map);
		size_t next = fn(&state_);
		fmt::print("Exited basic block. Next: {:#x}\n", next);
		fmt::print(state_dump());

		pc_ = next;
	}
}

std::string emu::state_dump() const
{
	std::string repr;

	repr += fmt::format("pc: {:#x}\n", pc_);
	for (size_t i = 0; i < 32;) {
		repr += fmt::format("r{:02}: {:#016x} ", i, state_.regs[i]);
		i++;
		if (i % 8 == 0)
			repr += '\n';
	}

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

	return assemble(lifter_.amd64_target(), instrs, ff.body_lbl_);
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
	return {map, size};
}
} // namespace dyn
