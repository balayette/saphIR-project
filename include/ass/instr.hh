#pragma once

#include <string>
#include <vector>
#include "utils/temp.hh"

namespace assem
{
struct instr {
	instr(const std::string &repr, std::vector<::temp::temp> dst,
	      std::vector<::temp::temp> src, std::vector<::temp::label> jmps);

	virtual ~instr() = default;

	virtual std::string to_string() const;

	std::string repr_;
	std::vector<::temp::temp> dst_;
	std::vector<::temp::temp> src_;
	std::vector<::temp::label> jmps_;
};

struct oper : public instr {
	oper(const std::string &repr, std::vector<::temp::temp> dst,
	     std::vector<::temp::temp> src, std::vector<::temp::label> jmps);
};

struct label : public instr {
	label(const std::string &repr, ::temp::label lab);
	::temp::label lab_;
};

struct move : public instr {
	move(const std::string &repr, std::vector<::temp::temp> dst,
	     std::vector<::temp::temp> src);
};
} // namespace assem
