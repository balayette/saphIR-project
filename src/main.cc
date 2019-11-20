#include <iostream>
#include "stmt.hh"
#include "driver.hh"
#include "exp.hh"
#include "pretty-printer.hh"
#include "default-visitor.hh"
#include "transforms.hh"
#include "sema.hh"
#include "translate.hh"

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

        frontend::translate::translate_visitor t;
        drv.prog_->accept(t);

	drv.prog_->accept(p);

	delete drv.prog_;

	return 0;
}
