#pragma once

namespace utils
{
static inline int64_t syscall(uint64_t syscall_nr, uint64_t arg1)
{
	int64_t ret;

	asm volatile("syscall\n"
		     : "=a"(ret)
		     : "a"(syscall_nr), "D"(arg1)
		     : "memory", "rcx", "r11");

	return ret;
}
} // namespace utils
