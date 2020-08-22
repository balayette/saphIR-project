#pragma once

#include "ir/ir.hh"

/*
 * This runs simplification passes on the IR
 * Current simplification passes:
 * - Remove AND and OR from binops
 */
namespace ir
{
tree::rnode simplify(tree::rnode tree);
}
