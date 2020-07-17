#include "frontend/stmt.hh"
#include "mach/target.hh"

namespace frontend
{
std::ostream &operator<<(std::ostream &os, const vardec &dec)
{
	os << dec.type_->to_string() << ' ' << dec.name_;
	if (dec.escapes_)
		os << '^';
	return os;
}

tydec::tydec(symbol name) : dec(nullptr, name) {}
} // namespace frontend
