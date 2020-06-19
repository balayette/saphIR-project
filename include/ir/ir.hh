#pragma once

#include "utils/symbol.hh"
#include "utils/temp.hh"
#include "frontend/ops.hh"
#include "frontend/exp.hh"
#include "frontend/types.hh"
#include "visitors/ir-visitor.hh"
#include "utils/ref.hh"
#include "utils/assert.hh"

/*
 * IR representation: basically Appel's IR, but typed.
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
	braceinit,
	name,
	temp,
	binop,
	unaryop,
	mem,
	call,
	eseq,
	move,
	sexp,
	jump,
	cjump,
	seq,
	label,
	asm_block,
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
	exp() = default;
	exp(utils::ref<types::ty> ty) : ty_(ty) { ASSERT(ty, "Type is null"); }

	utils::ref<types::ty> ty_;
	size_t size() const { return ty_->size(); }
	size_t assem_size() const { return ty_->assem_size(); }
};

struct stm : public ir_node {
};

using rexp = utils::ref<exp>;
using rstm = utils::ref<stm>;

struct cnst : public exp {
	// XXX: Constants are all 8 bytes integer at the moment
	cnst(int value) : exp(types::integer_type()), value_(value) {}

	TREE_KIND(cnst)

	int64_t value_;
};

struct braceinit : public exp {
	braceinit(utils::ref<types::ty> &ty, const std::vector<rexp> &exps)
	    : exp(ty)
	{
		children_.insert(children_.end(), exps.begin(), exps.end());
	}

	std::vector<rexp> exps()
	{
		std::vector<rexp> ret;
		for (auto &c : children_)
			ret.push_back(c.as<exp>());
		return ret;
	}

	TREE_KIND(braceinit)
};

struct name : public exp {
	// Jump destinations can be names, but they don't have a type.
	name(const utils::label &label) : label_(label) {}
	name(const utils::label &label, utils::ref<types::ty> ty)
	    : exp(ty), label_(label)
	{
	}
	TREE_KIND(name)

	utils::label label_;
};

struct temp : public exp {
	temp(const utils::temp &temp, utils::ref<types::ty> ty)
	    : exp(ty), temp_(temp)
	{
	}
	TREE_KIND(temp)

	utils::temp temp_;
};

struct binop : public exp {
	binop(ops::binop op, rexp lhs, rexp rhs, utils::ref<types::ty> ty)
	    : exp(ty), op_(op)
	{
		children_.emplace_back(lhs);
		children_.emplace_back(rhs);
	}
	TREE_KIND(binop)

	rexp lhs() { return children_[0].as<exp>(); }
	rexp rhs() { return children_[1].as<exp>(); }

	ops::binop op_;
};

struct unaryop : public exp {
	unaryop(ops::unaryop op, rexp e, utils::ref<types::ty> type)
	    : exp(type), op_(op)
	{
		children_.emplace_back(e);
	}
	TREE_KIND(unaryop)

	rexp e() { return children_[0].as<exp>(); }

	ops::unaryop op_;
};

struct mem : public exp {
	mem(rexp e)
	{
		ty_ = types::deref_pointer_type(e->ty_);
		children_.emplace_back(e);
	}
	TREE_KIND(mem)

	rexp e() { return children_[0].as<exp>(); }
};

struct call : public exp {
	call(const rexp &f, const std::vector<rexp> &args,
	     utils::ref<types::ty> type)
	    : exp(type)
	{
		children_.emplace_back(f);
		children_.insert(children_.end(), args.begin(), args.end());
		auto fty = ty_.as<types::fun_ty>();
		ASSERT(fty, "Type is not a fun_ty");
		fun_ty_ = fty;
		ty_ = fty->ret_ty_;
		variadic_ = fty->variadic_;
	}

	TREE_KIND(call)

	rexp f() { return children_[0].as<exp>(); }

	std::vector<rexp> args()
	{
		std::vector<rexp> args;
		for (auto it = children_.begin() + 1; it != children_.end();
		     ++it)
			args.emplace_back(it->as<exp>());
		return args;
	}

	bool variadic() { return variadic_; }

	utils::ref<types::fun_ty> fun_ty_;

      private:
	bool variadic_;
};

struct eseq : public exp {
	eseq(rstm lhs, rexp rhs) : exp(rhs->ty_) { children_ = {lhs, rhs}; }
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

struct asm_block : public stm {
	asm_block(const std::vector<std::string> &lines,
		  const std::vector<utils::temp> &reg_in,
		  const std::vector<utils::temp> &reg_out,
		  const std::vector<utils::temp> &reg_clob)
	    : lines_(lines), reg_in_(reg_in), reg_out_(reg_out),
	      reg_clob_(reg_clob)
	{
	}

	TREE_KIND(asm_block)

	std::vector<std::string> lines_;
	std::vector<utils::temp> reg_in_;
	std::vector<utils::temp> reg_out_;
	std::vector<utils::temp> reg_clob_;
};
} // namespace ir::tree
