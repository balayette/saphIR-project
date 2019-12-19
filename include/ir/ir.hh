#pragma once

#include "utils/symbol.hh"
#include "utils/temp.hh"
#include "frontend/ops.hh"
#include "frontend/exp.hh"
#include "visitors/ir-visitor.hh"
#include "utils/ref.hh"

/*
 * IR representation: basically Appel's IR.
 */

#define TREE_KIND(X)                                                           \
	virtual tree_kind kind() override { return tree_kind::X; }             \
	virtual void accept(ir_visitor &visitor) override                      \
	{                                                                      \
		visitor.visit_##X(*this);                                      \
	}

namespace ir::tree
{
enum class tree_kind {
	cnst,
	name,
	temp,
	binop,
	mem,
	call,
	eseq,
	move,
	sexp,
	jump,
	cjump,
	seq,
	label
};

struct ir_node {
      protected:
	ir_node() = default;
	ir_node(const ir_node &rhs) = default;
	ir_node &operator=(const ir_node &rhs) = default;

      public:
	virtual ~ir_node() = default;
	virtual tree_kind kind() = 0;

	virtual void accept(ir_visitor &visitor) = 0;

	std::vector<utils::ref<ir_node>> children_;
};

using rnode = utils::ref<ir_node>;
using rnodevec = std::vector<rnode>;

struct exp : public ir_node {
};

struct stm : public ir_node {
};

using rexp = utils::ref<exp>;
using rstm = utils::ref<stm>;

struct cnst : public exp {
	cnst(int value) : value_(value) {}
	TREE_KIND(cnst);

	int value_;
};

struct name : public exp {
	name(const utils::label &label) : label_(label) {}
	TREE_KIND(name)

	utils::label label_;
};

struct temp : public exp {
	temp(const utils::temp &temp) : temp_(temp) {}
	TREE_KIND(temp)

	utils::temp temp_;
};

struct binop : public exp {
	binop(ops::binop op, rexp lhs, rexp rhs) : op_(op)
	{
		children_.emplace_back(lhs);
		children_.emplace_back(rhs);
	}
	TREE_KIND(binop)

	rexp lhs() { return children_[0].as<exp>(); }
	rexp rhs() { return children_[1].as<exp>(); }

	ops::binop op_;
};

struct mem : public exp {
	mem(rexp e) { children_.emplace_back(e); }
	TREE_KIND(mem)

	rexp e() { return children_[0].as<exp>(); }
};

struct call : public exp {
	call(const rexp &name, const std::vector<rexp> &args)
	{
		children_.emplace_back(name);
		children_.insert(children_.end(), args.begin(), args.end());
	}
	TREE_KIND(call)

	rexp name() { return children_[0].as<exp>(); }

	std::vector<rexp> args()
	{
		std::vector<rexp> args;
		for (auto it = children_.begin() + 1; it != children_.end();
		     ++it)
			args.emplace_back(it->as<exp>());
		return args;
	}
};

struct eseq : public exp {
	eseq(rstm lhs, rexp rhs) { children_ = {lhs, rhs}; }
	TREE_KIND(eseq)

	rstm lhs() { return children_[0].as<stm>(); }
	rexp rhs() { return children_[1].as<exp>(); }
};

struct move : public stm {
	move(rexp lhs, rexp rhs) { children_ = {lhs, rhs}; }
	TREE_KIND(move);

	rexp lhs() { return children_[0].as<exp>(); }
	rexp rhs() { return children_[1].as<exp>(); };
};

struct sexp : public stm {
	sexp(rexp e) { children_ = {e}; }
	TREE_KIND(sexp)

	rexp e() { return children_[0].as<exp>(); }
};

struct jump : public stm {
	jump(rexp dest, const std::vector<utils::label> &avlbl_dests)
	    : avlbl_dests_(avlbl_dests)
	{
		children_ = {dest};
	}
	TREE_KIND(jump)
	rexp dest() { return children_[0].as<exp>(); }

	std::vector<utils::label> avlbl_dests_;
};

struct cjump : public stm {
	cjump(ops::cmpop op, rexp lhs, rexp rhs, const utils::label &ltrue,
	      const utils::label &lfalse)
	    : op_(op), ltrue_(ltrue), lfalse_(lfalse)
	{
		children_ = {lhs, rhs};
	}
	TREE_KIND(cjump)
	rexp lhs() { return children_[0].as<exp>(); }
	rexp rhs() { return children_[1].as<exp>(); }

	ops::cmpop op_;
	utils::label ltrue_;
	utils::label lfalse_;
};

struct seq : public stm {
	seq(const std::vector<rstm> &body)
	{
		for (auto c : body)
			children_.push_back(c);
	}
	TREE_KIND(seq)

	std::vector<rstm> body()
	{
		std::vector<rstm> ret;
		for (auto c : children_)
			ret.emplace_back(c.as<stm>());
		return ret;
	}
};

struct label : public stm {
	label(const utils::label &name) : name_(name) {}
	TREE_KIND(label)

	utils::label name_;
};
} // namespace ir::tree
