#pragma once

/*
 * IR representation: basically Appel's IR.
 */

namespace backend
{
struct ir_node {
      protected:
	ir_node() = default;
	ir_node(const ir_node &rhs) = default;
	ir_node &operator=(const ir_node &rhs) = default;
      public:
	virtual ~ir_node() = default;
	virtual void accept()
};
} // namespace backend
