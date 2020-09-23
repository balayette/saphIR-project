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

static inline int64_t syscall(uint64_t syscall_nr, uint64_t arg1,
			       uint64_t arg2, uint64_t arg3, uint64_t arg4,
			       uint64_t arg5, uint64_t arg6)
{
	int64_t ret;

	asm volatile(
		"mov %[arg4], %%r10\n"
		"mov %[arg5], %%r8\n"
		"mov %[arg6], %%r9\n"
		"syscall\n"
		: "=a"(ret)
		: "a"(syscall_nr), "D"(arg1), "S"(arg2), "d"(arg3),
		  [ arg4 ] "r"(arg4), [ arg5 ] "r"(arg5), [ arg6 ] "r"(arg6)
		: "memory", "r10", "r8", "r9", "rcx", "r11");

	return ret;
}
} // namespace utils
