#include <iostream>
#include <getopt.h>
#include "utils/fs.hh"
#include "dyn/emu.hh"
#include "dyn/unicorn-emu.hh"
#include "fmt/format.h"
#include <string>
#include <optional>

struct options {
	std::optional<std::string> coverage_file;
	std::string binary;
	bool help;
	bool singlestep;
};

options parse_options(int argc, char **argv)
{
	int opt = 0;
	options ret{};

	while ((opt = getopt(argc, argv, "shc:")) != -1 && !ret.help) {
		if (opt == 'c')
			ret.coverage_file = optarg;
		else if (opt == 'h')
			ret.help = true;
		else if (opt == 's')
			ret.singlestep = true;
		else {
			fmt::print("option '{}' not recognized\n", (char)opt);
			ret.help = true;
		}
	}

	if (optind == argc)
		ret.help = true;
	else
		ret.binary = argv[optind];

	return ret;
}

int main(int argc, char *argv[])
{
	auto opts = parse_options(argc, argv);
	if (opts.help) {
		fmt::print("{} [-c coverage_output] [-s] [-h] binary\n",
			   argv[0]);
		return 1;
	}

	utils::mapped_file file(opts.binary);
	dyn::emu emu(file, dyn::emu_params(opts.singlestep));

	std::ofstream coverage_file;

	if (opts.coverage_file) {
		coverage_file.open(*opts.coverage_file);
		emu.add_on_entry_callback([&](uint64_t pc) {
			coverage_file << fmt::format("{:#x}\n", pc);
		});
	}

	emu.init();
	emu.setup();
	emu.run();

	fmt::print("Exited: {}\n", emu.exit_code());
}
