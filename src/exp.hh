#pragma once

#include "visitor.hh"
#include "symbol.hh"
#include "types.hh"
#include <vector>

namespace frontend
{
enum class binop { MINUS, PLUS, MULT, DIV };
enum class cmpop { EQ, NEQ };

const std::string &binop_to_string(binop op);
const std::string &cmpop_to_string(cmpop op);

struct fundec;
struct dec;

struct exp {
      protected:
	exp() : ty_(types::type::INVALID) {}
	exp(const exp &rhs) = default;
	exp &operator=(const exp &rhs) = default;

      public:
	virtual ~exp() = default;
	virtual void accept(visitor &visitor) = 0;

	types::ty ty_;
};

struct bin : public exp {
	bin(binop op, exp *lhs, exp *rhs) : exp(), op_(op), lhs_(lhs), rhs_(rhs)
	{
	}

	~bin() override
	{
		delete lhs_;
		delete rhs_;
	}

	void accept(visitor &visitor) override { visitor.visit_bin(*this); }

	binop op_;
	exp *lhs_;
	exp *rhs_;
};

struct cmp : public exp {
	cmp(cmpop op, exp *lhs, exp *rhs) : op_(op), lhs_(lhs), rhs_(rhs)
	{
		ty_ = types::type::INT;
	}

	virtual ~cmp() override
	{
		delete lhs_;
		delete rhs_;
	}

	ACCEPT(cmp)

	cmpop op_;
	exp *lhs_;
	exp *rhs_;
};

struct num : public exp {
	num(int value) : value_(value) { ty_ = types::type::INT; }

	ACCEPT(num)

	int value_;
};

struct ref : public exp {
	ref(symbol name) : name_(name), dec_(nullptr) {}

	ACCEPT(ref)

	symbol name_;

	dec *dec_;
};

struct deref : public exp {
	deref(exp *e) : e_(e) {}

	ACCEPT(deref)

	virtual ~deref() override { delete e_; }

	exp *e_;
};

struct addrof : public exp {
	addrof(exp *e) : e_(e) {}

	ACCEPT(addrof)

	virtual ~addrof() override { delete e_; }

	exp *e_;
};

struct call : public exp {
	call(symbol name, std::vector<exp *> args)
	    : name_(name), args_(args), fdec_(nullptr)
	{
	}

	ACCEPT(call)

	virtual ~call() override
	{
		for (auto *a : args_)
			delete a;
	}

	symbol name_;
	std::vector<exp *> args_;

	fundec *fdec_;
};

struct str_lit : public exp {
	str_lit(const std::string &str) : str_(str)
	{
		ty_ = types::type::STRING;
	}

	ACCEPT(str_lit)

	std::string str_;
};
} // namespace frontend
