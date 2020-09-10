#pragma once

#include "ref.hh"

namespace utils
{
template <typename T> ref<T>::ref(T *ptr) : std::shared_ptr<T>(ptr) {}

template <typename T> bool ref<T>::operator==(const T *rhs)
{
	return std::shared_ptr<T>::get() == rhs;
}

template <typename T> bool ref<T>::operator!=(const T *rhs)
{
	return !(*this == rhs);
}

template <typename T> bool ref<T>::operator==(std::nullptr_t rhs)
{
	return std::shared_ptr<T>::get() == rhs;
}

template <typename T> bool ref<T>::operator!=(std::nullptr_t rhs)
{
	return !(*this == rhs);
}

template <typename T> T *ref<T>::operator&() const { return this->get(); }

template <typename T>
inline std::ostream &operator<<(std::ostream &os, const ref<T> &p)
{
	return os << *p;
}

template <typename T> template <typename Dest> ref<Dest> ref<T>::as()
{
	return std::dynamic_pointer_cast<Dest>(*this);
}

template <typename T> template <typename Dest> ref<Dest> ref<T>::as() const
{
	return std::dynamic_pointer_cast<Dest>(*this);
}

template <typename T>
template <typename Dest>
ref<T>::ref(const ref<Dest> &rhs) : std::shared_ptr<T>(rhs)
{
}

template <typename T>
template <typename Dest>
ref<T>::ref(const std::shared_ptr<Dest> &rhs) : std::shared_ptr<T>(rhs)
{
}
} // namespace utils
