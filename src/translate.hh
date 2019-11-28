#pragma once

#include "ir.hh"

namespace frontend::translate
{
class exp
{
      public:
	virtual ~exp() = default;

	virtual backend::tree::exp *un_ex() = 0;
	virtual backend::tree::stm *un_nx() = 0;
	virtual backend::tree::stm *un_cx(const temp::label &t,
					  const temp::label &f) = 0;
};

class cx : public exp
{
      public:
	cx(frontend::cmpop op, backend::tree::exp *l, backend::tree::exp *r);

	backend::tree::exp *un_ex() override;
	backend::tree::stm *un_nx() override;
	backend::tree::stm *un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	frontend::cmpop op_;
	backend::tree::exp *l_;
	backend::tree::exp *r_;
};

class ex : public exp
{
      public:
	ex(backend::tree::exp *e);
	backend::tree::exp *un_ex() override;
	backend::tree::stm *un_nx() override;
	backend::tree::stm *un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::exp *e_;
};

class nx : public exp
{
      public:
	nx(backend::tree::stm *s);
	backend::tree::exp *un_ex() override;
	backend::tree::stm *un_nx() override;
	backend::tree::stm *un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::stm *s_;
};
} // namespace frontend::translate
