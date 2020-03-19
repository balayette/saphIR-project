#pragma once

#include <string>
#include <vector>

#include "frontend/stmt.hh"
#include "frontend/parser/parser.hh"

#define YY_DECL yy::parser::symbol_type yylex(driver &d)

YY_DECL;

class driver
{
      public:
	driver();

	int parse(const std::string &file);

	void scan_begin();
	void scan_end();

	yy::location location_;
	utils::ref<frontend::decs> prog_;

      private:
	bool debug_parsing_;
	bool debug_scanning_;
	std::string file_;
};
