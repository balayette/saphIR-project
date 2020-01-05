#include "ir/canon/bb.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "utils/assert.hh"

namespace ir
{
bb::bb(tree::rnodevec::iterator begin, tree::rnodevec::iterator end)
    : instrs_(tree::rnodevec(begin, end))
{
}

std::vector<utils::label> bb::successors()
{
	if (auto cjump = instrs_.back().as<tree::cjump>())
		return {cjump->ltrue_, cjump->lfalse_};
	if (auto jump = instrs_.back().as<tree::jump>())
		return jump->avlbl_dests_;
	// epilogue
	return {};
}

utils::label bb::entry()
{
	auto lbl = instrs_.front().as<tree::label>();
	ASSERT(lbl != nullptr,
	       "First instruction of a basic block not a label.");
	return lbl->name_;
}

bool is_jump(tree::tree_kind k)
{
	return k == tree::tree_kind::cjump || k == tree::tree_kind::jump;
}

std::unordered_map<utils::label, bb>
create_bbs(tree::rnode stm, utils::label &prologue, utils::label epilogue)
{
	// stm is a seq, and is the only seq/eseq in the program.
	auto seq = stm.as<tree::seq>();

	tree::rnodevec::iterator bb_begin = seq->children_.begin();
	std::vector<bb> basic_blocks;

	tree::rnodevec stmts;

	for (auto ichild = seq->children_.begin();
	     ichild < seq->children_.end(); ichild++) {
		if (!is_jump((*ichild)->kind())
		    && (*ichild)->kind() != tree::tree_kind::label) {
			stmts.emplace_back(*ichild);
			continue;
		}

		std::cout << "Reached the end of a block\n";

		// End the block and start a new one.

		if (bb_begin == seq->children_.begin()) {
			// First block, we need to add a label if it doesn't
			// have one, and tell the prologue to jump to it.
			// If the block already has a label, we use it.
			std::cout << " The block is the first block\n";
			if (stmts.size() > 0
			    && stmts.front()->kind() == tree::tree_kind::label)
				prologue =
					stmts.front().as<tree::label>()->name_;
			else {
				prologue = unique_label("prologue").get();
				stmts.insert(stmts.begin(),
					     new tree::label(prologue));
			}
			std::cout << " Prologue label: " << prologue << '\n';
		}

		auto child = *ichild;

		// If we're ending a block because we reached a jump, include
		// the jump in the block.
		// Otherwise, add a jump to the label
		if (is_jump(child->kind())) {
			std::cout << " The block was ended by a jump\n";
			stmts.push_back(*ichild);
			++ichild;
		} else {
			std::cout << " The block was ended by a label\n";
			auto lbl = child.as<tree::label>();
			stmts.emplace_back(new tree::jump(
				new tree::name(lbl->name_), {lbl->name_}));
			std::cout << "  Added a jump to " << lbl->name_ << '\n';
		}

		// At this point we have a complete basic block.
		// If the basic block is a single jump, then we can remove it,
		// because no label => no one can jump to it.
		std::cout << " Block completed\n";
		if (stmts.size() > 1 && !is_jump(stmts.front()->kind())) {
			bb block(stmts.begin(), stmts.end());
			basic_blocks.push_back(block);
		}

		bb_begin = ichild;
		stmts.clear();

		// If we ended on a label, include it in the next block.
		if (ichild != seq->children_.end()
		    && (*ichild)->kind() == tree::tree_kind::label)
			stmts.push_back(*ichild);
	}

	if (bb_begin != seq->children_.end()) {
		std::cout << "Adding the epilogue block\n";
		bb block(bb_begin, seq->children_.end());
		block.instrs_.push_back(
			new tree::jump(new tree::name(epilogue), {epilogue}));

		basic_blocks.push_back(block);
	}

	std::unordered_map<utils::label, bb> ret;
	for (auto block : basic_blocks) {
		std::cout << "Block " << block.entry() << " ->";
		for (auto s : block.successors())
			std::cout << " " << s;
		std::cout << "\n";
		ret.insert({block.entry(), block});
	}

	return ret;
}
} // namespace ir
