#pragma once

#include "exp.hh"

class num : public exp
{
      public:
	num(int value) : exp(), value_(value) {}

      private:
	int value_;
}
