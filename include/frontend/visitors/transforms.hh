#pragma once
#include "default-visitor.hh"

namespace frontend::transforms
{
class unique_ids_visitor : public default_visitor
{
	/*
	 * We could go over call and ref, but by the time this is called, their
	 * fdec_ and dec_ fields are filled in and should be used for all
	 * compiler uses. We leave the names to their original values to make
	 * debugging what they refer to easier to understand.
	 * */
      public:
	virtual void visit_locdec(locdec &s) override;
	virtual void visit_globaldec(globaldec &s) override;
};
} // namespace frontend::transforms
