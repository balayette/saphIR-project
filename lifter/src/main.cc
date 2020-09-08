#include "lifter/lifter.hh"
#include <fstream>
#include "ir/visitors/ir-pretty-printer.hh"
#include "keystone/keystone.h"
#include "elf/elf.hh"
#include "utils/fs.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/trace.hh"
#include "backend/graph-regalloc.hh"
#include "backend/linear-regalloc.hh"

std::pair<void *, size_t> assemble(mach::target &target,
				   std::vector<assem::rinstr> &instrs,
				   utils::label body_lbl, utils::label epi_lbl)
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

	ks_engine *ks;
	ASSERT(ks_open(KS_ARCH_X86, KS_MODE_64, &ks) == KS_ERR_OK,
	       "Couldn't init keystone");
	ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

	uint8_t *out;
	size_t size, count;
	if (ks_asm(ks, text.c_str(), 0, &out, &size, &count) != KS_ERR_OK) {
		std::cout << ks_strerror(ks_errno(ks)) << '\n';
		UNREACHABLE("Couldn't assemble");
	}

	fmt::print("Assembled to {} instruction ({} bytes)\n", count, size);

	void *map = mmap(NULL, size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
	ASSERT(map != MAP_FAILED, "Couldn't mmap");
	std::memcpy(map, out, size);
	mprotect(map, size, PROT_READ | PROT_EXEC);

	return std::make_pair(map, size);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		std::cerr << "usage: lifter_main <binary>\n";
		return 2;
	}

	utils::mapped_file file(argv[1]);
	elf::elf bin(file);

	auto entry = bin.ehdr().entry();

	const elf::program_header *code = bin.segment_for_address(entry);
	ASSERT(code, "No segment for entry point");

	lifter::lifter lifter;
	lifter::disas disas;

	auto code_view = code->contents(file) + (entry - code->vaddr());

	auto bb = disas.next(code_view.data(), code_view.size(), entry);
	std::cout << bb.dump() << '\n';

	auto ff = lifter.lift(bb);

	auto canon = ir::canon(ff.body_);
	auto bbs = ir::create_bbs(canon, ff.body_lbl_, ff.epi_lbl_);

	auto traces = ir::create_traces(bbs, ff.body_lbl_);
	auto trace = ir::optimize_traces(traces);
	trace.push_back(lifter.amd64_target().make_label(ff.epi_lbl_));

	auto generator = lifter.amd64_target().make_asm_generator();
	generator->codegen(trace);
	auto instrs = generator->output();
	ff.frame_->proc_entry_exit_2(instrs);

	backend::regalloc::linear_alloc(instrs, ff);

	auto [map, size] = assemble(lifter.amd64_target(), instrs, ff.body_lbl_,
				    ff.epi_lbl_);

	fmt::print("Basic block: {} ({} bytes)\n", map, size);
}
