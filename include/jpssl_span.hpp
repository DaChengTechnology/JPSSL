#pragma once
/**
 * jpssl_span.hpp -- jpssl::span 兼容层
 *
 * C++20 起直接复用 std::span（零开销别名）；
 * C++17（及 C++11/14）提供行为兼容的最小自实现，
 * 覆盖本项目使用的成员：data/size/empty/operator[]/front/back/
 * begin/end/subspan/first/last 以及从指针+长度、数组、std::array、
 * 容器（vector/string）构造，并支持静态 extent（Extent 模板参数）。
 *
 * 说明：静态 extent 的 (pointer, size_type) 构造在本实现中宽松允许
 * （与 MSVC 的 std::span 行为一致），便于旧调用点无缝迁移。
 */

#include <cstddef>
#include <array>
#include <iterator>
#include <type_traits>

#if defined(__cpp_lib_span) && __cpp_lib_span >= 202002L

#include <span>

namespace jpssl {

template <typename T, std::size_t Extent = std::dynamic_extent>
using span = std::span<T, Extent>;

} // namespace jpssl

#else

namespace jpssl {

template <typename T, std::size_t Extent = static_cast<std::size_t>(-1)>
class span {
public:
    using element_type = T;
    using value_type = typename std::remove_cv<T>::type;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using iterator = T*;
    using const_iterator = const T*;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    // 默认构造仅对动态 extent 可用（与 std::span 语义一致）。
    template <bool HasDefault = (Extent == static_cast<std::size_t>(-1)),
              typename std::enable_if<HasDefault, int>::type = 0>
    span() noexcept : ptr_(nullptr), size_(0) {}

    span(pointer ptr, size_type count) : ptr_(ptr), size_(count) {}
    // 仅当第二个参数为指针时启用：避免 (ptr, 0) 中整数 0 与空指针常量
    // 同时匹配 pointer/size 与 pointer/pointer 两个重载导致的歧义。
    template <typename End,
              typename std::enable_if<std::is_pointer<End>::value, int>::type = 0>
    span(pointer first, End last) : ptr_(first),
                                    size_(static_cast<size_type>(last - first)) {}

    // C 数组（const 与非 const 均可，由 T 决定）。
    template <std::size_t N>
    span(T (&arr)[N]) noexcept : ptr_(arr), size_(N) {}

    // std::array。
    template <std::size_t N>
    span(std::array<value_type, N>& arr) noexcept : ptr_(arr.data()), size_(N) {}
    template <std::size_t N>
    span(const std::array<value_type, N>& arr) noexcept : ptr_(arr.data()), size_(N) {}

    // 容器（vector / string / span 等提供 data()+size() 的类型）。
    template <typename Container,
              typename std::enable_if<
                  !std::is_array<Container>::value &&
                  !std::is_pointer<Container>::value &&
                  std::is_convertible<decltype(std::declval<Container&>().data()),
                                      pointer>::value,
                  int>::type = 0>
    span(Container& cont) : ptr_(cont.data()),
                            size_(static_cast<size_type>(cont.size())) {}

    template <typename Container,
              typename std::enable_if<
                  !std::is_array<Container>::value &&
                  !std::is_pointer<Container>::value &&
                  std::is_convertible<decltype(std::declval<const Container&>().data()),
                                      pointer>::value,
                  int>::type = 0>
    span(const Container& cont) : ptr_(cont.data()),
                                  size_(static_cast<size_type>(cont.size())) {}

    pointer data() const noexcept { return ptr_; }
    size_type size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    reference operator[](size_type i) const { return ptr_[i]; }
    reference front() const { return ptr_[0]; }
    reference back() const { return ptr_[size_ - 1]; }

    iterator begin() const noexcept { return ptr_; }
    iterator end() const noexcept { return ptr_ + size_; }
    const_iterator cbegin() const noexcept { return ptr_; }
    const_iterator cend() const noexcept { return ptr_ + size_; }
    reverse_iterator rbegin() const noexcept { return reverse_iterator(end()); }
    reverse_iterator rend() const noexcept { return reverse_iterator(begin()); }

    span<T> subspan(size_type offset) const {
        return span<T>(ptr_ + offset, size_ - offset);
    }
    span<T> subspan(size_type offset, size_type count) const {
        return span<T>(ptr_ + offset, count);
    }
    span<T> first(size_type count) const { return span<T>(ptr_, count); }
    span<T> last(size_type count) const {
        return span<T>(ptr_ + (size_ - count), count);
    }

private:
    pointer ptr_;
    size_type size_;
};

} // namespace jpssl

#endif
