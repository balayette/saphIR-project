#pragma once

#include "ir/ir.hh"
#include "utils/ref.hh"

/*
 * I don't think that I need to do the whole commutation thing, because my
 * language is quite different from Tiger.
 * XXX: I could be wrong.
 */
namespace ir
{
tree::rnode canon(tree::rnode tree);
}
