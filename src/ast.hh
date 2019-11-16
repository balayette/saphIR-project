#pragma once
#include <vector>
#include "symbol.hh"
#include "visitor.hh"

enum class binop { ASSIGN, EQ, MINUS, PLUS, MULT, DIV };

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
      public:
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

struct num : public exp {
      public:
	num(int value) : value_(value) {}

	void accept(visitor &visitor) override { visitor.visit_num(*this); }

	int value_;
};

struct seq : public exp {
      public:
	std::vector<exp *> children_;

	~seq() override
	{
		for (auto *exp : children_)
			delete exp;
	}

	void accept(visitor &visitor) override { visitor.visit_seq(*this); }
};

struct id : public exp {
      public:
	id(const symbol &id) : id_(id) {}

	void accept(visitor &visitor) override { visitor.visit_id(*this); }

	symbol id_;
};

struct fun : public exp {
	fun(id *name, std::vector<id *> params, seq *body)
	    : name_(name), params_(params), body_(body)
	{
	}

	~fun() override
	{
		delete name_;
		delete body_;
		for (auto *p : params_)
			delete p;
	}

	void accept(visitor &visitor) override { visitor.visit_fun(*this); }

	id *name_;
	std::vector<id *> params_;
	seq *body_;
};

inline std::string binop_str[] = {"=", "==", "-", "+", "*", "/"};

inline std::ostream &operator<<(std::ostream &os, binop op)
{
	return os << binop_str[static_cast<int>(op)];
}
