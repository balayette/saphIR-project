#pragma once
#include <vector>
#include "symbol.hh"

enum class binop { ASSIGN, EQ, MINUS, PLUS, MULT, DIV };

class exp
{
      protected:
	exp() = default;
	exp(const exp &rhs) = default;
	exp &operator=(const exp &rhs) = default;

      public:
	virtual ~exp() = default;
};

class program
{
      public:
	program(exp *e) : e_(e) {}

      private:
	exp *e_;
};


class bin : public exp
{
      public:
	bin(binop op, exp *lhs, exp *rhs) : exp(), op_(op), lhs_(lhs), rhs_(rhs)
	{
	}

	~bin() override
	{
		delete lhs_;
		delete rhs_;
	}


      private:
	binop op_;
	exp *lhs_;
	exp *rhs_;
};

class num : public exp
{
      public:
	num(int value) : value_(value) {}

      private:
	int value_;
};

class seq : public exp
{
      public:
	std::vector<exp *> children_;

	~seq() override
	{
		for (auto *exp : children_)
			delete exp;
	}
};

class id : public exp
{
      public:
	id(const symbol &id) : id_(id) {}

      private:
	symbol id_;
};
