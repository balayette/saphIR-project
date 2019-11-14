#include "driver.hh"

#include "parser.hh"

driver::driver() : debug_parsing_(true), debug_scanning_(true) {}

int driver::parse(const std::string &file)
{
	file_ = file;
	location_.initialize(&file_);

	scan_begin();

	yy::parser parse(*this);
	int ret = parse();

	scan_end();

	return ret;
}
