#pragma once

#include <string>
#include <chrono>

#define TIMER_ENABLE 1

#if TIMER_ENABLE
#define TIMER(N, M) utils::timer N(M)
#else
#define TIMER(N, M)
#endif

namespace utils
{
class timer
{
      public:
	timer(const std::string &message);
	~timer();

      private:
	std::string message_;
	std::chrono::time_point<std::chrono::steady_clock> start_;
};
} // namespace utils
