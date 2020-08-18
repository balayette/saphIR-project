#pragma once

#include "utils/symbol.hh"
#include "utils/temp.hh"
#include "ir/ops.hh"
#include "ir/types.hh"
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
	sext,
	zext,
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
	ir_node(mach::target &target) : target_(target) {}
	ir_node(const ir_node &ir_node) = default;

      public:
	virtual ~ir_node() = default;
	virtual tree_kind kind() = 0;

	virtual void accept(ir_visitor &visitor) = 0;

	mach::target &target_;
	std::vector<utils::ref<ir_node>> children_;
};

using rnode = utils::ref<ir_node>;
using rnodevec = std::vector<rnode>;

struct exp : public ir_node {
	exp(mach::target &target) : ir_node(target) {}
	exp(mach::target &target, utils::ref<types::ty> ty)
	    : ir_node(target), ty_(ty)
	{
		ASSERT(ty, "Type is null");
	}

	size_t size() const { return ty_->size(); }
	size_t assem_size() const { return ty_->assem_size(); }

	utils::ref<types::ty> ty() const { return ty_; }

	utils::ref<types::ty> ty_;
};

struct stm : public ir_node {
	stm(mach::target &target) : ir_node(target) {}
};

using rexp = utils::ref<exp>;
using rstm = utils::ref<stm>;

struct cnst : public exp {
	cnst(mach::target &target, uint64_t value);
	cnst(mach::target &target, uint64_t value, types::signedness signedness,
	     size_t size);

	TREE_KIND(cnst)

	uint64_t value_;
};

struct braceinit : public exp {
	braceinit(mach::target &target, utils::ref<types::ty> &ty,
		  const std::vector<rexp> &exps)
	    : exp(target, ty)
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
	name(mach::target &target, const utils::label &label)
	    : exp(target), label_(label)
	{
	}
	name(mach::target &target, const utils::label &label,
	     utils::ref<types::ty> ty)
	    : exp(target, ty), label_(label)
	{
	}
	TREE_KIND(name)

	utils::label label_;
};

struct temp : public exp {
	temp(mach::target &target, const utils::temp &temp,
	     utils::ref<types::ty> ty)
	    : exp(target, ty), temp_(temp)
	{
	}
	TREE_KIND(temp)

	utils::temp temp_;
};

struct binop : public exp {
	binop(mach::target &target, ops::binop op, rexp lhs, rexp rhs,
	      utils::ref<types::ty> ty)
	    : exp(target, ty), op_(op)
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
	unaryop(mach::target &target, ops::unaryop op, rexp e,
		utils::ref<types::ty> type)
	    : exp(target, type), op_(op)
	{
		children_.emplace_back(e);
	}
	TREE_KIND(unaryop)

	rexp e() { return children_[0].as<exp>(); }

	ops::unaryop op_;
};

struct mem : public exp {
	mem(mach::target &target, rexp e) : exp(target)
	{
		ty_ = types::deref_pointer_type(e->ty_);
		children_.emplace_back(e);
	}

	TREE_KIND(mem)

	rexp e() { return children_[0].as<exp>(); }
};

struct call : public exp {
	call(mach::target &target, const rexp &f, const std::vector<rexp> &args,
	     utils::ref<types::ty> type)
	    : exp(target, type)
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
	eseq(mach::target &target, rstm lhs, rexp rhs) : exp(target, rhs->ty_)
	{
		children_ = {lhs, rhs};
	}
	TREE_KIND(eseq)

	rstm lhs() { return children_[0].as<stm>(); }
	rexp rhs() { return children_[1].as<exp>(); }
};

struct sext : public exp {
	sext(mach::target &target, rexp e, utils::ref<types::ty> type)
	    : exp(target, type)
	{
		children_ = {e};
	}
	TREE_KIND(sext)

	rexp e() { return children_[0].as<exp>(); }
};

struct zext : public exp {
	zext(mach::target &target, rexp e, utils::ref<types::ty> type)
	    : exp(target, type)
	{
		children_ = {e};
	}
	TREE_KIND(zext)

	rexp e() { return children_[0].as<exp>(); }
};

struct move : public stm {
	move(mach::target &target, rexp lhs, rexp rhs) : stm(target)
	{
		children_ = {lhs, rhs};
	}
	TREE_KIND(move);

	rexp lhs() { return children_[0].as<exp>(); }
	rexp rhs() { return children_[1].as<exp>(); };
};

struct sexp : public stm {
	sexp(mach::target &target, rexp e) : stm(target) { children_ = {e}; }
	TREE_KIND(sexp)

	rexp e() { return children_[0].as<exp>(); }
};

struct jump : public stm {
	jump(mach::target &target, rexp dest,
	     const std::vector<utils::label> &avlbl_dests)
	    : stm(target), avlbl_dests_(avlbl_dests)
	{
		children_ = {dest};
	}
	TREE_KIND(jump)
	rexp dest() { return children_[0].as<exp>(); }

	std::vector<utils::label> avlbl_dests_;
};

struct cjump : public stm {
	cjump(mach::target &target, ops::cmpop op, rexp lhs, rexp rhs,
	      const utils::label &ltrue, const utils::label &lfalse)
	    : stm(target), op_(op), ltrue_(ltrue), lfalse_(lfalse)
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
	seq(mach::target &target, const std::vector<rstm> &body) : stm(target)
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
	label(mach::target &target, const utils::label &name)
	    : stm(target), name_(name)
	{
	}
	TREE_KIND(label)

	utils::label name_;
};

struct asm_block : public stm {
	asm_block(mach::target &target, const std::vector<std::string> &lines,
		  const std::vector<utils::temp> &reg_in,
		  const std::vector<utils::temp> &reg_out,
		  const std::vector<utils::temp> &reg_clob)
	    : stm(target), lines_(lines), reg_in_(reg_in), reg_out_(reg_out),
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
