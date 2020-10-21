#pragma once

#include <string>
#include <chrono>

#define TIMER_ENABLE 1

#if TIMER_ENABLE
#define TIMER(N, M) utils::timer N(M)
#define TIMERN(N, M, C) utils::timer N(M, C)
#else
#define TIMER(N, M)
#define TIMERN(N, M, C)
#endif

namespace utils
{
class timer
{
      public:
	timer(const std::string &message, unsigned element_count = 0);
	~timer();

      private:
	std::string message_;
	unsigned element_count_;
	std::chrono::time_point<std::chrono::steady_clock> start_;
};
} // namespace utils
