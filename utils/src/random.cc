#include <cstdint>
namespace utils
{
struct xorshift_state {
	uint64_t a;
};
thread_local xorshift_state state;

void seed(uint64_t seed) { state.a = seed; }
} // namespace utils
