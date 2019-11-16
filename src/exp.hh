#pragma once

#include "visitor.hh"
#include "symbol.hh"

enum class binop { MINUS, PLUS, MULT, DIV };
enum class cmpop { EQ, NEQ };

struct exp {
      protected:
	exp() = default;
	exp(const exp &rhs) = default;
	exp &operator=(const exp &rhs) = default;

      public:
	virtual ~exp() = default;
	virtual void accept(visitor &visitor) = 0;
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

struct ass : public exp {
	ass(symbol id, exp *rhs) : id_(id), rhs_(rhs) {}

	virtual ~ass() override { delete rhs_; }

	ACCEPT(ass)

	symbol id_;
	exp *rhs_;
};

struct cmp : public exp {
	cmp(cmpop op, exp *lhs, exp *rhs) : op_(op), lhs_(lhs), rhs_(rhs) {}

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
	num(int value) : value_(value) {}

	ACCEPT(num)

	int value_;
};

struct ref : public exp {
	ref(symbol name) : name_(name) {}

	ACCEPT(ref)

	symbol name_;
};

struct call : public exp {
	call(symbol name, std::vector<exp *> args) : name_(name), args_(args) {}

	ACCEPT(call)

	symbol name_;
	std::vector<exp *> args_;
};
