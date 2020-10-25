#include "utils/assert.hh"
#include <iostream>
#include <string>

namespace utils
{
void assertion_failed(const std::string &file, size_t line,
		      const std::string &fun, const std::string &cond,
		      const std::string &msg, unsigned retcode)
{
	std::cerr << file << ":" << line << ":" << fun << " - `" << cond
		  << "` failed: " << msg << '\n';
	std::abort();
	std::exit(retcode);
}

std::string cfail_strs[] = {
	"Lexing",
	"Parsing",
	"Semantic analysis",
	"Translation",
};

const std::string &cfail_str(cfail error)
{
	return cfail_strs[static_cast<unsigned>(error)];
}
} // namespace utils
