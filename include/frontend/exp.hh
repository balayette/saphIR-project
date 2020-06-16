#pragma once

#include "frontend/visitors/visitor.hh"
#include "utils/symbol.hh"
#include "types.hh"
#include "frontend/ops.hh"
#include "utils/ref.hh"
#include <vector>

namespace frontend
{
struct fundec;
struct funprotodec;
struct vardec;

struct exp {
      protected:
	exp()
	    : ty_(new types::builtin_ty(types::type::INVALID,
					types::signedness::INVALID))
	{
	}
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
	cmp(ops::cmpop op, utils::ref<exp> lhs, utils::ref<exp> rhs)
	    : op_(op), lhs_(lhs), rhs_(rhs)
	{
		ty_ = new types::builtin_ty(types::type::INT, 4,
					    types::signedness::UNSIGNED);
	}

	ACCEPT(cmp)

	ops::cmpop op_;
	utils::ref<exp> lhs_;
	utils::ref<exp> rhs_;
};

struct num : public exp {
	num(int64_t value) : value_(value)
	{
		ty_ = new types::builtin_ty(types::type::INT, 4,
					    types::signedness::SIGNED);
	}

	ACCEPT(num)

	int64_t value_;
};

struct ref : public exp {
	ref(symbol name) : name_(name), dec_(nullptr) {}

	ACCEPT(ref)

	symbol name_;

	vardec *dec_;
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
	call(symbol name, std::vector<utils::ref<exp>> args)
	    : name_(name), args_(args), fdec_(nullptr)
	{
	}

	ACCEPT(call)

	symbol name_;
	std::vector<utils::ref<exp>> args_;

	funprotodec *fdec_;
};

struct str_lit : public exp {
	str_lit(const std::string &str) : str_(str)
	{
		ty_ = new types::builtin_ty(types::type::STRING,
					    types::signedness::INVALID);
	}

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
