#include "driver/driver.hh"

#include "frontend/parser/parser.hh"

driver::driver() : debug_parsing_(false), debug_scanning_(false) {}

int driver::parse(const std::string &file)
{
	file_ = file;
	location_.initialize(&file_);

	scan_begin();

	yy::parser parse(*this);
	parse.set_debug_level(0);
	int ret = parse();

	scan_end();

	return ret;
}
