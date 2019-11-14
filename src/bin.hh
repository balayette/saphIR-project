#pragma once

#include "exp.hh"

enum class binop { ASSIGN, EQ, MINUS, PLUS, MULT, DIV };

class bin : public exp
{
      public:
	bin(binop op, exp *lhs, exp *rhs) : exp(), op_(op), lhs_(lhs), rhs_(rhs)
	{
	}

	~Bin() override
	{
		delete lhs_;
		delete rhs_;
	}

      private:
	binop op_;
	exp *lhs_;
	exp *rhs_;
};
