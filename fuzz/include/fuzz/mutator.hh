#pragma once

#include <vector>
#include "fmt/format.h"
#include "utils/random.hh"

namespace fuzz
{
struct input {
	input(size_t sz) { data.resize(sz); }

	size_t random_index() const
	{
		return utils::rand(0ul, data.size() - 1);
	}

	std::string to_string() const
	{
		std::string ret;

		for (size_t i = 0; i < data.size(); i++) {
			ret += fmt::format("{:#04x} ", data[i]);
			if ((i + 1) % 8 == 0)
				ret += "\n";
		}

		return ret;
	}

	std::vector<uint8_t> data;
};

class database
{
      public:
	virtual ~database() = default;

	void add(const input &input) { inputs_.push_back(input); }

	const input &operator[](size_t i) const { return inputs_[i]; }
	input &operator[](size_t i) { return inputs_[i]; }

	size_t size() const { return inputs_.size(); }

      private:
	std::vector<input> inputs_;
};

class mutator
{
      public:
	mutator(database &db, size_t max_sz) : db_(db), max_sz_(max_sz) {}

	input default_input() { return input(max_sz_); }

	input mutate(input &in, size_t rounds = 3) const;

      private:
	void mutate_round(input &inpt) const;

	database &db_;
	size_t max_sz_;
};
} // namespace fuzz
