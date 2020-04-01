#include <iostream>
#include <fstream>
#include "driver/driver.hh"
#include "frontend/visitors/pretty-printer.hh"
#include "frontend/visitors/transforms.hh"
#include "frontend/sema/sema.hh"
#include "frontend/sema/tycheck.hh"
#include "frontend/visitors/translate.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/trace.hh"
#include "backend/cfg.hh"
#include "backend/liveness.hh"
#include "backend/regalloc.hh"
#include "backend/opt/peephole.hh"
#include "mach/codegen.hh"
#include "utils/assert.hh"

int usage(char *pname)
{
	std::cerr << "usage: " << pname << " in.jit out.S\n";
	return 1;
}

int main(int argc, char *argv[])
{
	if (argc != 3)
		return usage(argv[0]);

	driver drv;
	if (drv.parse(argv[1])) {
		COMPILATION_ERROR(utils::cfail::PARSING);
	}

	std::ofstream fout(argv[2]);

	frontend::pretty_printer p(std::cout);
	drv.prog_->accept(p);

	frontend::sema::binding_visitor b;
	drv.prog_->accept(b);

	frontend::sema::tycheck_visitor tc;
	drv.prog_->accept(tc);

	frontend::transforms::unique_ids_visitor u;
	drv.prog_->accept(u);

	frontend::sema::escapes_visitor e;
	drv.prog_->accept(e);

	frontend::sema::frame_visitor f;
	drv.prog_->accept(f);

	drv.prog_->accept(p);

	frontend::translate::translate_visitor trans;
	drv.prog_->accept(trans);

	ir::ir_pretty_printer pir(std::cout);

	std::vector<mach::fun_fragment> frags;
	for (auto &frag : trans.funs_) {
		std::cout << "Function: " << frag.frame_.s_
			  << " - Return label : " << frag.ret_lbl_ << '\n';
		frags.push_back(frag);
	}

	if (trans.init_fun_)
		frags.push_back(*trans.init_fun_);

	std::vector<mach::asm_function> funs;

	for (auto &frag : frags) {
		std::cout << "Precannon:\n";
		frag.body_->accept(pir);
		auto canoned = ir::canon(frag.body_);
		std::cout << "\nCannoned:\n";
		canoned->accept(pir);
		std::cout << "--\n";

		auto bbs =
			ir::create_bbs(canoned, frag.body_lbl_, frag.epi_lbl_);

		for (auto [_, v] : bbs) {
			std::cout << "+++++++++++++++++++++++++++++++++++++\n";
			for (auto s : v.instrs_) {
				s->accept(pir);
			}
		}
		std::cout << "+++++++++++++++++++++++++++++++++++++\n";

		auto traces = ir::create_traces(bbs, frag.body_lbl_);
		auto trace = ir::optimize_traces(traces);
		trace.push_back(new ir::tree::label(frag.epi_lbl_));

		std::cout << "Trace:\n";
		std::cout << "-------------------------------------\n";
		for (auto s : trace)
			s->accept(pir);
		std::cout << "-------------------------------------\n";

		std::cout << "==========\n";
		auto instrs = mach::codegen(frag.frame_, trace);

		frag.frame_.proc_entry_exit_2(instrs);
		frag.frame_.proc_entry_exit_3(instrs, frag.body_lbl_,
					      frag.ret_lbl_);

		backend::cfg cfg(instrs, frag.body_lbl_);
		std::ofstream cfg_out(std::string("cfg") + frag.frame_.s_.get()
				      + std::string(".dot"));
		cfg.cfg_.dump_dot(cfg_out);

		backend::ifence_graph ifence(cfg.cfg_);
		std::ofstream ifence_out(std::string("ifence")
					 + frag.frame_.s_.get()
					 + std::string(".dot"));
		ifence.graph_.dump_dot(ifence_out, false);

		std::cout << "######################\n";

		backend::regalloc::alloc(instrs, frag);
		backend::opt::peephole(instrs);
		auto f = frag.frame_.proc_entry_exit_3(instrs, frag.body_lbl_,
						       frag.epi_lbl_);

		funs.push_back(f);
	}

	fout << "\t.section .rodata\n";
	for (auto [lab, s] : trans.str_lits_)
		fout << mach::asm_string(lab, s.str_);
	fout << '\n';

	for (auto &glob : drv.prog_->decs_) {
		if (glob.as<globaldec>())
			fout << "\t.lcomm .L_" << glob->name_ << ", 8\n";
	}
	fout << "\n";

	if (trans.init_fun_) {
		fout << "\t.section .init_array\n";
		fout << "\t.quad " << trans.init_fun_->frame_.s_ << "\n";
		fout << "\n";
	}

	fout << "\t.text\n";
	for (auto &f : funs) {
		fout << f.prologue_;
		for (auto &i : f.instrs_) {
			if (i->repr_.size() == 0)
				continue;
			if (!i.as<assem::label>())
				fout << '\t';
			fout << i->to_string(mach::temp_map()) << '\n';
		}
		fout << f.epilogue_;
		fout << '\n';
	}

	return 0;
}
