#include "driver.hh"

#include "parser.hh"

driver::driver() : debug_parsing_(true), debug_scanning_(true) {}

driver::parse(const std::string &file)
{
	file_ = file;
	location_.initialize(&file);

	scan_begin();

	yy::parser parse(*this);
	parse.set_debug_level(debug_parsing_);
	int ret = parse();

	scan_end();

	return ret;
}
