#include "utils/timer.hh"
#include "fmt/format.h"

namespace utils
{
timer::timer(const std::string &message)
    : message_(message), start_(std::chrono::steady_clock::now())
{
	fmt::print("--- TASK {} BEGIN ---\n", message_);
}

timer::~timer()
{
	std::chrono::duration<double> s =
		std::chrono::steady_clock::now() - start_;
	fmt::print("--- TASK {} END [{}s] ---\n", message_, s.count());
}
} // namespace utils
