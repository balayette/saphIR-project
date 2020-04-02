#pragma once

#include <string>
#include <vector>
#include <ostream>
#include <utility>
#include "utils/ref.hh"
#include "utils/temp.hh"

namespace assem
{
struct instr {
	instr(const std::string &repr, std::vector<utils::temp> dst,
	      std::vector<utils::temp> src, std::vector<utils::label> jmps);

	virtual ~instr() = default;
	virtual std::string repr() const;
	virtual std::string to_string() const;
	virtual std::string to_string(
		const std::unordered_map<utils::temp, std::string> &map) const;

      protected:
	std::string repr_;

      public:
	std::vector<utils::temp> dst_;
	std::vector<utils::temp> src_;
	std::vector<utils::label> jmps_;
};

std::ostream &operator<<(std::ostream &os, const instr &ins);


using rinstr = utils::ref<instr>;

struct oper : public instr {
	oper(const std::string &repr, std::vector<utils::temp> dst,
	     std::vector<utils::temp> src, std::vector<utils::label> jmps);
};

struct lea : public oper {
	lea(utils::temp dst, std::pair<std::string, utils::temp> src);
	lea(utils::temp dst, std::string src);

	std::string repr() const override;
	std::string lhs_;
};

struct label : public instr {
	label(const std::string &repr, utils::label lab);
	utils::label lab_;
};

struct move : public instr {
	move(std::vector<utils::temp> dst, std::vector<utils::temp> src);
};
} // namespace assem
