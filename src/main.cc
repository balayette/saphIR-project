#include <iostream>
#include "driver/driver.hh"
#include "frontend/visitors/pretty-printer.hh"
#include "frontend/visitors/transforms.hh"
#include "frontend/sema/sema.hh"
#include "frontend/visitors/translate.hh"
#include "ir/visitors/ir-pretty-printer.hh"

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
		std::cerr << "Parsing failed.\n";
		return 2;
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

	backend::ir_pretty_printer pir(std::cout);
	for (auto &frag : trans.funs_) {
		std::cout << "Function: " << frag.frame_.s_
			  << " - Return label : " << frag.ret_lbl_ << '\n';
		frag.body_->accept(pir);
	}

	delete drv.prog_;

	return 0;
}
