#pragma once

#include <string>
#include <vector>
#include <ostream>
#include <utility>
#include "utils/ref.hh"
#include "utils/temp.hh"
#include "frontend/types.hh"

namespace assem
{
std::string format_repr(std::string repr, std::vector<std::string> src,
			std::vector<std::string> dst);

struct temp {
	temp(const utils::temp &t, unsigned size = 8,
	     types::signedness is_signed = types::signedness::SIGNED)
	    : temp_(t), size_(size), is_signed_(is_signed)
	{
	}
	temp(unsigned size = 8,
	     types::signedness is_signed = types::signedness::SIGNED)
	    : temp_(utils::temp()), size_(size), is_signed_(is_signed)
	{
	}

	operator utils::temp &() { return temp_; }
	operator const utils::temp &() const { return temp_; }
	operator std::string() const
	{
		return std::string(temp_) + "_" + std::to_string(size_)
		       + (is_signed_ == types::signedness::SIGNED ? "s" : "u");
	}

	// == and != are used by the register allocator, and do not take the
	// size into account
	bool operator==(const temp &rhs) const { return temp_ == rhs.temp_; }
	bool operator!=(const temp &rhs) const { return temp_ != rhs.temp_; }

	utils::temp temp_;
	unsigned size_;
	types::signedness is_signed_;
};

inline std::ostream &operator<<(std::ostream &os, const temp &t)
{
	return os << std::string(t);
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

struct jump : public oper {
	jump(const std::string &repr, std::vector<assem::temp> src,
	     std::vector<utils::label> jumps);
};

struct label : public instr {
	label(const std::string &repr, utils::label lab);
	utils::label lab_;
};

struct move : public instr {
	move(const std::string &dst_str, const std::string &src_str,
	     std::vector<assem::temp> dst, std::vector<assem::temp> src);

	virtual std::string to_string(
		std::function<std::string(utils::temp, unsigned)> f) const = 0;

	virtual bool is_simple_move() const { return false; }
	virtual bool removable() const { return false; }

	std::string dst_str_;
	std::string src_str_;
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
