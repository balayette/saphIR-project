#include <iostream>
#include "driver.hh"
#include "pretty-printer.hh"

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

	pretty_printer p(std::cout);
	drv.prog_->accept(p);

	return 0;
}
