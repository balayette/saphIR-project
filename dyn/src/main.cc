#include <iostream>
#include "utils/fs.hh"
#include "dyn/emu.hh"

int main(int argc, char *argv[])
{
	if (argc != 2) {
		std::cerr << "usage: dyn binary\n";
		return 1;
	}

	utils::mapped_file file(argv[1]);
	dyn::emu emu(file);

	emu.setup();
	emu.run();
}
