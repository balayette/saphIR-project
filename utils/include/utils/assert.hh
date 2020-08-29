#pragma once

#include <string>
#include "fmt/format.h"

#define ASSERT(cond, ...)                                                      \
	do {                                                                   \
		if (!(cond))                                                   \
			utils::assertion_failed(__FILE__, __LINE__, __func__,  \
						#cond,                         \
						fmt::format(__VA_ARGS__));     \
	} while (0)

#define UNREACHABLE(...)                                                       \
	do {                                                                   \
		utils::assertion_failed(__FILE__, __LINE__, __func__,          \
					"unreachable code",                    \
					fmt::format(__VA_ARGS__));             \
	} while (0)

#define COMPILATION_ERROR(error)                                               \
	do {                                                                   \
		utils::assertion_failed(__FILE__, __LINE__, __func__,          \
					utils::cfail_str(error), "exiting",    \
					static_cast<unsigned>(error));         \
	} while (0)

namespace utils
{
enum class cfail { LEXING, PARSING, SEMA, TRANS };

const std::string &cfail_str(cfail error);
void __attribute__((noreturn))
assertion_failed(const std::string &file, size_t line, const std::string &fun,
		 const std::string &cond, const std::string &msg,
		 unsigned retcode = 42);
} // namespace utils
