#pragma once

#include <vector>
#include <iostream>

/*
 * The graph class is a bit tricky.
 * A graph<T> contains a vector of gnode<T>s.
 * A gnode<T> is basically a wrapper around the type in the graph, which
 * stores the value of the node, and vectors of successors and predecessors.
 *
 * All gnode<T>s in the graph have an id, which is used to acces them.
 * Internally, the node_id is the index of the node in the vector of gnode<T>s.
 * This means that it is not possible to remove nodes from a graph at the
 * moment.
 *
 * There are two access methodes:
 * - T* get(node_id), which returns the value of the gnode associated with the
 *   id
 * - gnode<T>& node(node_id), which returns the gnode associated with the id.
 *
 * To iterate over all the nodes of a graph, one can use the values() method,
 * which copies the values to a vector, or iterate over nodes_ids in the range
 * [0, graph.size()[
 */

namespace utils
{
using node_id = size_t;

template <typename T> class gnode
{
      public:
	gnode(T value);
	T &operator*();
	T *operator->();

	const T &operator*() const;
	const T *operator->() const;

	T elm_;

	const std::vector<node_id> &preds() const { return pred_; }
	const std::vector<node_id> &succs() const { return succ_; }

	std::vector<node_id> &preds() { return pred_; }
	std::vector<node_id> &succs() { return succ_; }

      private:
	std::vector<node_id> pred_;
	std::vector<node_id> succ_;
};

template <typename T> class graph
{
      public:
	node_id add_node(T value);
	node_id get_or_insert(T value);
	void add_edge(node_id n1, node_id n2);

	T *get(node_id idx);
	const T *get(node_id idx) const;

	void dump_dot(std::ostream &os, bool directed = true) const;
	size_t size() const;

	std::vector<T> values() const;
	const std::vector<gnode<T>> &nodes() const { return nodes_; }
	const gnode<T> &node(node_id idx) const { return nodes_[idx]; }

      private:
	std::vector<gnode<T>> nodes_;
};
} // namespace utils

#include "graph.hxx"
