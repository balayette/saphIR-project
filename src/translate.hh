#pragma once

#include "ir.hh"

namespace frontend::translate
{
class exp
{
      public:
	virtual ~exp() = default;

	virtual backend::tree::rexp un_ex() = 0;
	virtual backend::tree::rstm un_nx() = 0;
	virtual backend::tree::rstm un_cx(const temp::label &t,
					  const temp::label &f) = 0;
};

class cx : public exp
{
      public:
	cx(frontend::cmpop op, backend::tree::rexp l, backend::tree::rexp r);

	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	frontend::cmpop op_;
	backend::tree::rexp l_;
	backend::tree::rexp r_;
};

class ex : public exp
{
      public:
	ex(backend::tree::rexp e);
	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::rexp e_;
};

class nx : public exp
{
      public:
	nx(backend::tree::rstm s);
	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::rstm s_;
};
} // namespace frontend::translate
