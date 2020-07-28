#include <iostream>
#include "utils/fs.hh"
#include "elf/elf.hh"

int main(int argc, char *argv[])
{
	if (argc != 2) {
		std::cerr << "usage: readelf <binary>\n";
		return 1;
	}

	utils::mapped_file file(argv[1]);
	elf::elf bin(file);

	std::cout << bin.dump();
}
