#include <sstream>

#include "asm-writer/asm-writer.hh"

namespace asm_writer
{
std::string asm_writer::str() const
{
	std::stringstream s;
	to_stream(s);

	return s.str();
}

void asm_writer::add_strings(
	const std::unordered_map<utils::label, std::string> &strs)
{
	for (const auto &[k, v] : strs)
		add_string(k, v);
}
} // namespace asm_writer
