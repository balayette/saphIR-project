#pragma once

#include <string>
#include <vector>
#include <ostream>
#include <utility>
#include "utils/ref.hh"
#include "utils/temp.hh"

namespace assem
{
struct temp {
	temp(const utils::temp &t, unsigned size = 8) : temp_(t), size_(size) {}
	temp(unsigned size = 8) : temp_(utils::temp()), size_(size) {}

	operator utils::temp &() { return temp_; }
	operator const utils::temp &() const { return temp_; }
	operator std::string() const { return temp_; }

	bool operator==(const temp &rhs) const { return temp_ == rhs.temp_; }
	bool operator!=(const temp &rhs) const { return temp_ != rhs.temp_; }

	utils::temp temp_;
	unsigned size_;
};

inline std::ostream &operator<<(std::ostream &os, const temp &t)
{
	return os << t.temp_ << std::to_string(t.size_);
}

using temp_endomap = std::unordered_map<temp, temp>;
using temp_set = utils::uset<temp>;
using temp_pair = std::pair<temp, temp>;
using temp_pair_set = utils::uset<temp_pair>;

struct instr {
	instr(const std::string &repr, std::vector<assem::temp> dst,
	      std::vector<assem::temp> src, std::vector<utils::label> jmps);

	virtual ~instr() = default;
	virtual std::string repr() const;
	virtual std::string to_string() const;
	virtual std::string to_string(
		const std::unordered_map<utils::temp, std::string> &map) const;
	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f) const;

      protected:
	std::string repr_;

      public:
	std::vector<assem::temp> dst_;
	std::vector<assem::temp> src_;
	std::vector<utils::label> jmps_;
};

std::ostream &operator<<(std::ostream &os, const instr &ins);


using rinstr = utils::ref<instr>;

struct oper : public instr {
	oper(const std::string &repr, std::vector<assem::temp> dst,
	     std::vector<assem::temp> src, std::vector<utils::label> jmps);
};

struct lea : public oper {
	lea(assem::temp dst, std::pair<std::string, assem::temp> src);
	lea(assem::temp dst, std::string src);

	std::string repr() const override;
	std::string lhs_;
};

struct label : public instr {
	label(const std::string &repr, utils::label lab);
	utils::label lab_;
};

struct move : public instr {
	move(std::vector<assem::temp> dst, std::vector<assem::temp> src);
};
} // namespace assem

namespace std
{
template <> struct hash<assem::temp> {
	std::size_t operator()(const assem::temp &t) const
	{
		return std::hash<std::string>{}(t.temp_.get());
	}
};

template <> struct hash<assem::temp_pair> {
	std::size_t operator()(const assem::temp_pair &p) const
	{
		return std::hash<assem::temp>{}(p.first)
		       + std::hash<assem::temp>{}(p.second);
	}
};
} // namespace std
