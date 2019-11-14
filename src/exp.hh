#pragma once

class exp
{
      protected:
	exp() = default;
	exp(const exp &rhs) = default;
	exp &operator=(const exp &rhs) = default;

      public:
	virtual ~exp();
};
