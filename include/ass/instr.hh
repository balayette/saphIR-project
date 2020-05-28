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
std::string size_str(unsigned sz);

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
		return std::string(temp_) + size_str(size_)
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

struct sized_oper : public oper {
	sized_oper(const std::string &oper_str, const std::string &op,
		   std::vector<assem::temp> dst, std::vector<assem::temp> src,
		   unsigned sz = 8);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	std::string oper_str_;
	std::string op_;
	unsigned sz_;
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
	move(const std::string &dst_str, const std::string &src_str,
	     std::vector<assem::temp> dst, std::vector<assem::temp> src);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	std::string dst_str_;
	std::string src_str_;
};

// a simple move is a reg2reg move
struct simple_move : public move {
	simple_move(assem::temp dst, assem::temp src);

	bool removable() const
	{
		return dst() == src() && dst().size_ <= src().size_;
	}

	assem::temp dst() const { return dst_[0]; }
	assem::temp src() const { return src_[0]; }
};

/*
 * a complex move is a reg2mem, mem2reg, imm2reg, imm2mem move
 * mem accesses go through registers with known sizes (assem::temps in the src
 * and dst vectors), but we also need the size of the data accessed or written
 * by the mem access.
 */
struct complex_move : public move {
	complex_move(const std::string &dst_str, const std::string &src_str,
		     std::vector<assem::temp> dst, std::vector<assem::temp> src,
		     unsigned dst_sz, unsigned src_sz, types::signedness sign);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	unsigned dst_sz_;
	unsigned src_sz_;

	types::signedness sign_;
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
