#include "utils/view.hh"

namespace utils
{
template <> std::string bufview<uint8_t>::dump() const
{
	std::string repr;

	for (size_t i = 0; i < size(); i++) {
		repr += fmt::format("{:#x} ", buf_[i]);
		if (i % 8 == 0)
			repr += "\n";
	}

	return repr;
}
} // namespace utils
