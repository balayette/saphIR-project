#pragma once

#include "ir/ir.hh"
#include "utils/ref.hh"

/*
 * In some languages, such as C, evaluation order is very loosely defined.
 * For example, in `*i = i++` the sides of the assignment can be evaluated in
 * any order.
 * Some IRs decide to force an evaluation order, but saphIR doesn't, because
 * it makes some codegen optimizations harder to apply.
 *
 * Linearization makes sure that there are no nested SEQs, CALLs and ESEQs.
 * CALLs must not be nested because that would cause problem during codegen
 * when parameters of nested calls compete for the same hardware registers.
 */
namespace ir
{
tree::rnode canon(tree::rnode tree);
}
