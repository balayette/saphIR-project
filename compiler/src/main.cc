#include <iostream>
#include <fstream>
#include <cstdlib>
#include <unistd.h>
#include <filesystem>
#include "driver/driver.hh"
#include "frontend/visitors/pretty-printer.hh"
#include "frontend/visitors/transforms.hh"
#include "frontend/sema/sema.hh"
#include "frontend/sema/tycheck.hh"
#include "frontend/visitors/translate.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "ir/visitors/ir-binop-optimizer.hh"
#include "ir/visitors/ir-arith-optimizer.hh"
#include "ir/visitors/ir-cloner-visitor.hh"
#include "ir/visitors/ir-cnst-obfuscator.hh"
#include "ir/canon/linearize.hh"
#include "ir/canon/bb.hh"
#include "ir/canon/trace.hh"
#include "ir/canon/simplify.hh"
#include "backend/cfg.hh"
#include "backend/liveness.hh"
#include "backend/graph-regalloc.hh"
#include "backend/linear-regalloc.hh"
#include "backend/opt/peephole.hh"
#include "mach/target.hh"
#include "mach/amd64/amd64-target.hh"
#include "mach/aarch64/aarch64-target.hh"
#include "utils/assert.hh"
#include "utils/timer.hh"
#include "asm-writer/elf/elf-asm-writer.hh"

struct options {
	options()
	    : help(false), src_path(nullptr), dst_path(nullptr),
	      optimize(false), obfuscate(false), arch("amd64")
	{
	}

	bool help;
	char *src_path;
	char *dst_path;
	bool optimize;
	bool obfuscate;
	std::string arch;
};

int usage(char *pname)
{
	std::cerr << "usage: " << pname
		  << " -i in.jit -o out.S [-O] [-P] [-m aarch64|amd64]\n";
	std::cerr << " -O : optimize\n";
	std::cerr << " -P : obfuscate\n";
	std::cerr << "Optimization removes some obfuscation techniques.\n";
	return 1;
}

std::string preprocess(const char *src_path)
{
	/*
	 * This is absolutely disgusting, but c++ doesn't allow us to create
	 * an fstream from a file descriptor...
	 */
	char tempf[] = "/tmp/XXXXXX";
	int fd = mkstemp(tempf);
	ASSERT(fd != -1, "Couldn't create temporary file");
	close(fd);

	auto cmd = fmt::format("cpp -ftrack-macro-expansion=0 -P '{}' > '{}'",
			       src_path, tempf);
	auto e = std::system(cmd.c_str());

	ASSERT(WIFEXITED(e) && WEXITSTATUS(e) == 0, "Preprocessing failed");

	return tempf;
}

options parse_options(int argc, char **argv)
{
	options ret;

	int opt = 0;
	while ((opt = getopt(argc, argv, "OPhm:o:i:")) != -1 && !ret.help) {
		if (opt == 'h')
			ret.help = true;
		else if (opt == 'o')
			ret.dst_path = optarg;
		else if (opt == 'i')
			ret.src_path = optarg;
		else if (opt == 'O')
			ret.optimize = true;
		else if (opt == 'P')
			ret.obfuscate = true;
		else if (opt == 'm')
			ret.arch = optarg;
		else {
			std::cerr << "option '" << (char)opt
				  << "' not recognized.\n";
			ret.help = true;
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	auto options = parse_options(argc, argv);

	if (options.help || !options.src_path || !options.dst_path)
		return usage(argv[0]);

	utils::ref<mach::target> target_ptr;
	if (options.arch == "amd64")
		target_ptr = new mach::amd64::amd64_target();
	else if (options.arch == "aarch64")
		target_ptr = new mach::aarch64::aarch64_target();
	else
		return usage(argv[0]);

	auto &target = *target_ptr;

	driver drv(target);

	auto pp_src = preprocess(options.src_path);

	if (drv.parse(pp_src)) {
		COMPILATION_ERROR(utils::cfail::PARSING);
	}

	std::filesystem::remove(pp_src);

	std::ofstream fout(options.dst_path);

	frontend::pretty_printer p(std::cout);
	drv.prog_->accept(p);

	frontend::sema::binding_visitor b;
	drv.prog_->accept(b);

	frontend::sema::tycheck_visitor tc(target);
	drv.prog_->accept(tc);

	frontend::transforms::unique_ids_visitor u;
	drv.prog_->accept(u);

	frontend::sema::escapes_visitor e;
	drv.prog_->accept(e);

	frontend::sema::frame_visitor f(target);
	drv.prog_->accept(f);

	drv.prog_->accept(p);

	frontend::translate::translate_visitor trans(target);
	drv.prog_->accept(trans);

	ir::ir_pretty_printer pir(std::cout);

	std::vector<mach::fun_fragment> frags;
	for (auto &frag : trans.funs_) {
		std::cout << "Function: " << frag.frame_->s_
			  << " - Return label : " << frag.ret_lbl_ << '\n';

		frags.push_back(frag);
	}

	if (options.obfuscate) {
		for (auto &frag : frags) {
			ir::ir_cnst_obfuscator obf(target);
			frag.body_ = obf.perform(frag.body_);
		}
	}

	if (options.optimize) {
		for (auto &frag : frags) {
			ir::ir_arith_optimizer arith_opt(target);
			frag.body_ = arith_opt.perform(frag.body_);

			ir::ir_binop_optimizer opt(target);
			frag.body_ = opt.perform(frag.body_);
		}
	}

	if (trans.init_fun_)
		frags.push_back(*trans.init_fun_);

	std::vector<mach::asm_function> funs;

	for (auto &frag : frags) {
		std::cout << "Precannon:\n";
		frag.body_->accept(pir);
		auto simplified = ir::simplify(frag.body_);
		auto canoned = ir::canon(simplified);
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
		trace.push_back(target.make_label(frag.epi_lbl_));

		std::cout << "Trace:\n";
		std::cout << "-------------------------------------\n";
		for (auto s : trace)
			s->accept(pir);
		std::cout << "-------------------------------------\n";

		std::cout << "==========\n";
		auto generator = target.make_asm_generator();
		generator->codegen(trace);
		auto instrs = generator->output();

		frag.frame_->add_live_registers(instrs);

		std::cout << "######################\n";

		if (options.optimize)
			backend::regalloc::graph_alloc(instrs, frag);
		else
			backend::regalloc::linear_alloc(instrs, frag);

		auto f = frag.frame_->make_asm_function(instrs, frag.body_lbl_,
							frag.epi_lbl_);

		funs.push_back(f);
	}

	asm_writer::elf_asm_writer writer(target);
	for (const auto &[n, s] : trans.str_lits_)
		writer.add_string(n, s.str_);
	for (const auto &glob : drv.prog_->decs_) {
		if (glob.as<globaldec>())
			writer.add_global(glob->name_, glob->type_->size());
	}
	if (trans.init_fun_)
		writer.add_init(trans.init_fun_->frame_->s_);
	writer.add_functions(funs);

	writer.to_stream(fout);

	return 0;
}
