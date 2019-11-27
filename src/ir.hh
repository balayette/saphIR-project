#pragma once

#include "symbol.hh"
#include "temp.hh"

/*
 * IR representation: basically Appel's IR.
 */

#define TREE_KIND(X)                                                           \
	virtual tree_kind kind() override { return tree_kind::X; }

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
};

struct exp : public ir_node {
};

struct stm : public ir_node {
};

struct cnst : public exp {
	cnst(int value) : value_(value) {}
	TREE_KIND(cnst);

	int value_;
};

struct name : public exp {
	name(const ::temp::label &label) : label_(label) {}
	TREE_KIND(cnst)

	::temp::label label_;
};

struct temp : public exp {
	temp(const ::temp::temp &temp) : temp_(temp) {}
	TREE_KIND(temp)

	::temp::temp temp_;
};

struct binop : public exp {
	binop(frontend::binop op, exp *lhs, exp *rhs)
	    : op_(op), lhs_(lhs), rhs_(rhs)
	{
	}
	TREE_KIND(binop)

	frontend::binop op_;
	exp *lhs_;
	exp *rhs_;
};

struct mem : public exp {
	mem(exp *e) : e_(e) {}
	TREE_KIND(mem)

	exp *e_;
};

struct call : public exp {
	call(const symbol &name, const std::vector<exp *> &args)
	    : name_(name), args_(args)
	{
	}
	TREE_KIND(call)

	symbol name_;
	std::vector<exp *> args_;
};

struct eseq : public exp {
	eseq(stm *lhs, exp *rhs) : lhs_(lhs), rhs_(rhs) {}
	TREE_KIND(eseq)

	stm *lhs_;
	exp *rhs_;
};

struct move : public stm {
	move(exp *lhs, exp *rhs) : lhs_(lhs), rhs_(rhs) {}
	TREE_KIND(move);

	exp *lhs_;
	exp *rhs_;
};

struct sexp : public stm {
	sexp(exp *e) : e_(e) {}
	TREE_KIND(sexp)

	exp *e_;
};

struct jump : public stm {
	jump(exp *dest, const std::vector<::temp::label> &avlbl_dests)
	    : dest_(dest), avlbl_dests_(avlbl_dests)
	{
	}
	TREE_KIND(jump)

	exp *dest_;
	std::vector<::temp::label> avlbl_dests_;
};

struct cjump : public stm {
	cjump(frontend::cmpop op, exp *lhs, exp *rhs,
	      const ::temp::label &ltrue, const ::temp::label &lfalse)
	    : op_(op), lhs_(lhs), rhs_(rhs), ltrue_(ltrue), lfalse_(lfalse)
	{
	}
	TREE_KIND(cjump)

	frontend::cmpop op_;
	exp *lhs_;
	exp *rhs_;
	::temp::label ltrue_;
	::temp::label lfalse_;
};

struct seq : public stm {
	seq(const std::vector<stm *> &body) : body_(body) {}
	TREE_KIND(seq)

	std::vector<stm *> body_;
};

struct label : public stm {
	label(const ::temp::label &name) : name_(name) {}
	TREE_KIND(label)

	::temp::label name_;
};
} // namespace backend::tree
