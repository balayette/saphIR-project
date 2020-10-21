#include "utils/timer.hh"
#include "fmt/format.h"

namespace utils
{
timer::timer(const std::string &message, unsigned element_count)
    : message_(message), element_count_(element_count),
      start_(std::chrono::steady_clock::now())
{
	if (!element_count_)
		fmt::print("--- TASK {} BEGIN ---\n", message_);
	else
		fmt::print("--- TASK {} BEGIN ({} elements) ---\n", message_,
			   element_count_);
}

timer::~timer()
{
	double s = std::chrono::duration_cast<std::chrono::microseconds>(
			   std::chrono::steady_clock::now() - start_)
			   .count()
		   / 1000000.0;

	if (!element_count_)
		fmt::print("--- TASK {} END   [{}s] ---\n", message_, s);
	else {
		fmt::print("--- TASK {} END   [{}s, {} its / sec] ---\n",
			   message_, s, (size_t)(element_count_ / s));
	}
}
} // namespace utils
