#pragma once

#include "scoped.hh"

namespace utils
{
template <typename K, typename V> scoped_map<K, V>::scoped_map()
{
	scopes_.emplace();
}

template <typename K, typename V> void scoped_map<K, V>::new_scope()
{
	scopes_.emplace(scopes_.top());
}

template <typename K, typename V> void scoped_map<K, V>::end_scope()
{
	scopes_.pop();
}

template <typename K, typename V> bool scoped_map<K, V>::add(const K &k, V v)
{
	auto [_, inserted] = scopes_.top().emplace(k, v);
	return inserted;
}

template <typename K, typename V>
std::optional<V> scoped_map<K, V>::get(const K &k)
{
	auto ret = scopes_.top().find(k);
	if (ret == scopes_.top().end())
		return std::nullopt;
	return ret->second;
}

template <typename K, typename V> size_t scoped_map<K, V>::size() const
{
	return scopes_.size();
}
} // namespace utils
