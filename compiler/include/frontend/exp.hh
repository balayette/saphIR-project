#pragma once

#include "frontend/visitors/visitor.hh"
#include "utils/symbol.hh"
#include "ir/types.hh"
#include "ir/ops.hh"
#include "utils/ref.hh"
#include <vector>

namespace frontend
{
struct dec;
struct fundec;
struct funprotodec;
struct vardec;

struct exp {
      protected:
	exp();
	exp(const utils::ref<types::ty> &ty) : ty_(ty) {}
	exp(const exp &rhs) = default;
	exp &operator=(const exp &rhs) = default;

      public:
	virtual ~exp() = default;
	virtual void accept(visitor &visitor) = 0;

	utils::ref<types::ty> ty_;
};

struct paren : public exp {
	paren(utils::ref<exp> e) : exp(), e_(e) {}

	void accept(visitor &visitor) override { visitor.visit_paren(*this); }

	utils::ref<exp> e_;
};

struct cast : public exp {
	cast(utils::ref<types::ty> ty, utils::ref<exp> e) : exp(ty), e_(e) {}

	void accept(visitor &visitor) override { visitor.visit_cast(*this); }

	utils::ref<exp> e_;
};

struct braceinit : public exp {
	braceinit(std::vector<utils::ref<exp>> exps) : exp(), exps_(exps) {}

	void accept(visitor &visitor) override
	{
		visitor.visit_braceinit(*this);
	}

	std::vector<utils::ref<exp>> exps_;
};

struct bin : public exp {
	bin(ops::binop op, utils::ref<exp> lhs, utils::ref<exp> rhs)
	    : exp(), op_(op), lhs_(lhs), rhs_(rhs)
	{
	}

	void accept(visitor &visitor) override { visitor.visit_bin(*this); }

	ops::binop op_;
	utils::ref<exp> lhs_;
	utils::ref<exp> rhs_;
};

struct unary : public exp {
	unary(ops::unaryop op, utils::ref<exp> e) : exp(), op_(op), e_(e) {}

	void accept(visitor &visitor) override { visitor.visit_unary(*this); }

	ops::unaryop op_;
	utils::ref<exp> e_;
};

struct cmp : public exp {
	cmp(ops::cmpop op, utils::ref<exp> lhs, utils::ref<exp> rhs);

	ACCEPT(cmp)

	ops::cmpop op_;
	utils::ref<exp> lhs_;
	utils::ref<exp> rhs_;
};

struct num : public exp {
	num(uint64_t value);

	ACCEPT(num)

	uint64_t value_;
};

struct ref : public exp {
	ref(symbol name) : name_(name), dec_(nullptr) {}

	ACCEPT(ref)

	symbol name_;

	dec *dec_;
};

struct deref : public exp {
	deref(utils::ref<exp> e) : e_(e) {}

	ACCEPT(deref)

	utils::ref<exp> e_;
};

struct addrof : public exp {
	addrof(utils::ref<exp> e) : e_(e) {}

	ACCEPT(addrof)

	utils::ref<exp> e_;
};

struct call : public exp {
	call(utils::ref<exp> f, std::vector<utils::ref<exp>> args)
	    : f_(f), args_(args)
	{
	}

	ACCEPT(call)

	utils::ref<exp> f_;
	std::vector<utils::ref<exp>> args_;
	utils::ref<types::ty> fty_;
};

struct str_lit : public exp {
	str_lit(const std::string &str);

	ACCEPT(str_lit)

	std::string str_;
};

struct memberaccess : public exp {
	memberaccess(utils::ref<exp> e, const symbol &member)
	    : e_(e), member_(member)
	{
	}

	ACCEPT(memberaccess)

	utils::ref<exp> e_;
	symbol member_;
};

struct arrowaccess : public exp {
	arrowaccess(utils::ref<exp> e, const symbol &member)
	    : e_(e), member_(member)
	{
	}

	ACCEPT(arrowaccess)

	utils::ref<exp> e_;
	symbol member_;
};

struct subscript : public exp {
	subscript(utils::ref<exp> base, utils::ref<exp> index)
	    : base_(base), index_(index)
	{
	}
	ACCEPT(subscript)

	utils::ref<exp> base_;
	utils::ref<exp> index_;
};
} // namespace frontend
