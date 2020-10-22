#include "fuzz/mutator.hh"
#include "utils/random.hh"

namespace fuzz
{
enum mutations {
	INC = 0,
	DEC,
	ADD,
	SUB,
	RAND,

	MUTATIONS_END,
};

input mutator::mutate(input &inpt, size_t rounds) const
{
	input ret = inpt;

	for (size_t i = 0; i < rounds; i++)
		mutate_round(ret);

	return ret;
}

void mutator::mutate_round(input &i) const
{
	auto mut = utils::rand(0, mutations::MUTATIONS_END - 1);

	if (mut == mutations::INC) {
		i.data[i.random_index()]++;
	} else if (mut == mutations::DEC) {
		i.data[i.random_index()]--;
	} else if (mut == mutations::ADD) {
		i.data[i.random_index()] += utils::rand(0, 255);
	} else if (mut == mutations::SUB) {
		i.data[i.random_index()] -= utils::rand(0, 255);
	} else if (mut == mutations::RAND) {
		i.data[i.random_index()] = utils::rand(0, 255);
	}
}
} // namespace fuzz
