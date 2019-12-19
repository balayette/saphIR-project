#include <iostream>
#include <fstream>
#include "driver/driver.hh"
#include "frontend/visitors/pretty-printer.hh"
#include "frontend/visitors/transforms.hh"
#include "frontend/sema/sema.hh"
#include "frontend/visitors/translate.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/trace.hh"
#include "backend/cfg.hh"
#include "mach/codegen.hh"
#include "utils/assert.hh"

int usage(char *pname)
{
	std::cerr << "usage: " << pname << " file\n";
	return 1;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
		return usage(argv[0]);

	driver drv;
	if (drv.parse(argv[1])) {
		COMPILATION_ERROR(utils::cfail::PARSING);
	}

	frontend::pretty_printer p(std::cout);
	drv.prog_->accept(p);

	frontend::sema::binding_visitor b;
	drv.prog_->accept(b);

	frontend::sema::escapes_visitor e;
	drv.prog_->accept(e);

	frontend::sema::frame_visitor f;
	drv.prog_->accept(f);

	frontend::transforms::unique_ids_visitor u;
	drv.prog_->accept(u);

	drv.prog_->accept(p);

	frontend::translate::translate_visitor trans;
	drv.prog_->accept(trans);

	ir::ir_pretty_printer pir(std::cout);
	for (auto &frag : trans.funs_) {
		std::cout << "Function: " << frag.frame_.s_
			  << " - Return label : " << frag.ret_lbl_ << '\n';
		frag.body_->accept(pir);
	}

	for (auto frag : trans.funs_) {
		auto canoned = ir::canon(frag.body_);
		std::cout << "Precannon:\n";
		frag.body_->accept(pir);
		std::cout << "\nCannoned:\n";
		canoned->accept(pir);
		std::cout << "--\n";

		utils::label pro;
		auto bbs = ir::create_bbs(canoned, pro);

		for (auto [_, v] : bbs) {
			std::cout << "----\n";
			for (auto s : v.instrs_) {
				s->accept(pir);
			}
		}

		std::cout << "Traces:\n";
		auto traces = ir::create_traces(bbs);
		auto trace = ir::optimize_traces(traces);
		std::cout << "-------------------------\n";
		for (auto s : trace)
			s->accept(pir);

		std::cout << "==========\n";
		auto instrs = mach::codegen(frag.frame_, trace);
		frag.frame_.proc_entry_exit_2(instrs);
		frag.frame_.proc_entry_exit_3(instrs);

		backend::cfg cfg(instrs, pro);
		std::ofstream out(std::string("cfg") + frag.frame_.s_.get()
				  + std::string(".dot"));
		cfg.cfg_.dump_dot(out);
	}

	delete drv.prog_;

	return 0;
}
