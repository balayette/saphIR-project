#include "frontend/stmt.hh"

namespace frontend
{
std::ostream &operator<<(std::ostream &os, const dec &dec)
{
	os << dec.type_.to_string() << ' ' << dec.name_;
	if (dec.escapes_)
		os << '^';
	return os;
}
} // namespace frontend
