#pragma once
#include "default-visitor.hh"
#include <iostream>
#include <string>

class pretty_printer : public default_visitor
{
      public:
	pretty_printer(std::ostream &s) : s_(s) {}

      private:
	std::ostream &s_;
};
