#pragma once

#include "symbol.hh"
#include "temp.hh"
#include "exp.hh"
#include "ir-visitor.hh"
#include "utils.hh"

/*
 * IR representation: basically Appel's IR.
 */

#define TREE_KIND(X)                                                           \
	virtual tree_kind kind() override { return tree_kind::X; }             \
	virtual void accept(ir_visitor &visitor) override                      \
	{                                                                      \
		visitor.visit_##X(*this);                                      \
	}

namespace backend::tree
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
};

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
	name(const ::temp::label &label) : label_(label) {}
	TREE_KIND(name)

	::temp::label label_;
};

struct temp : public exp {
	temp(const ::temp::temp &temp) : temp_(temp) {}
	TREE_KIND(temp)

	::temp::temp temp_;
};

struct binop : public exp {
	binop(frontend::binop op, rexp lhs, rexp rhs)
	    : op_(op), lhs_(lhs), rhs_(rhs)
	{
	}
	TREE_KIND(binop)

	frontend::binop op_;
	rexp lhs_;
	rexp rhs_;
};

struct mem : public exp {
	mem(rexp e) : e_(e) {}
	TREE_KIND(mem)

	rexp e_;
};

struct call : public exp {
	call(const symbol &name, const std::vector<rexp> &args)
	    : name_(name), args_(args)
	{
	}
	TREE_KIND(call)

	symbol name_;
	std::vector<rexp> args_;
};

struct eseq : public exp {
	eseq(rstm lhs, rexp rhs) : lhs_(lhs), rhs_(rhs) {}
	TREE_KIND(eseq)

	rstm lhs_;
	rexp rhs_;
};

struct move : public stm {
	move(rexp lhs, rexp rhs) : lhs_(lhs), rhs_(rhs) {}
	TREE_KIND(move);

	rexp lhs_;
	rexp rhs_;
};

struct sexp : public stm {
	sexp(rexp e) : e_(e) {}
	TREE_KIND(sexp)

	rexp e_;
};

struct jump : public stm {
	jump(rexp dest, const std::vector<::temp::label> &avlbl_dests)
	    : dest_(dest), avlbl_dests_(avlbl_dests)
	{
	}
	TREE_KIND(jump)

	rexp dest_;
	std::vector<::temp::label> avlbl_dests_;
};

struct cjump : public stm {
	cjump(frontend::cmpop op, rexp lhs, rexp rhs,
	      const ::temp::label &ltrue, const ::temp::label &lfalse)
	    : op_(op), lhs_(lhs), rhs_(rhs), ltrue_(ltrue), lfalse_(lfalse)
	{
	}
	TREE_KIND(cjump)

	frontend::cmpop op_;
	rexp lhs_;
	rexp rhs_;
	::temp::label ltrue_;
	::temp::label lfalse_;
};

struct seq : public stm {
	seq(const std::vector<rstm> &body) : body_(body) {}
	TREE_KIND(seq)

	std::vector<rstm> body_;
};

struct label : public stm {
	label(const ::temp::label &name) : name_(name) {}
	TREE_KIND(label)

	::temp::label name_;
};
} // namespace backend::tree
