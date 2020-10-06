/* Copyright (c) 2009-2020, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HOMA_INCLUDE_HOMA_UTIL_H
#define HOMA_INCLUDE_HOMA_UTIL_H

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <string>

/// Cast a member of a structure out to the containing structure.
template <class P, class M>
P*
container_of(M* ptr, const M P::*member)
{
    return (P*)((char*)ptr - (size_t) & (reinterpret_cast<P*>(0)->*member));
}

namespace Homa {
namespace Util {

/// Return the number of elements in a statically allocated array.
// This was taken from the RAMCloud project.
template <typename T, size_t length>
constexpr uint32_t
arrayLength(const T (&)[length])
{
    return length;
}

/**
 * Cast one size of int down to another one.
 * Asserts that no precision is lost at runtime.
 */
// This was taken from the RAMCloud project.
template <typename Small, typename Large>
Small
downCast(const Large& large)
{
    Small small = static_cast<Small>(large);
    // The following comparison (rather than "large==small") allows
    // this method to convert between signed and unsigned values.
    assert(large - small == 0);
    return small;
}

std::string demangle(const char* name);
std::string hexDump(const void* buf, uint64_t bytes);

/**
 * Return true if the given number is a power of 2; false, otherwise.
 */
template <typename num_type>
constexpr bool
isPowerOfTwo(num_type n)
{
    return (n > 0) && ((n & (n - 1)) == 0);
}

/**
 * This class is used to temporarily release lock in a safe fashion. Creating
 * an object of this class will unlock its associated mutex; when the object
 * is deleted, the mutex will be locked again. The template class T must be
 * a mutex-like class that supports lock and unlock operations.
 */
// This was taken from the RAMCloud project.
template <typename MutexType>
class unlock_guard {
  public:
    /**
     * Unlock the the provided mutex for the duration of this unlock_guards
     *  lifetime.
     */
    explicit unlock_guard(MutexType& mutex)
        : mutex(mutex)
    {
        mutex.unlock();
    }
    ~unlock_guard()
    {
        mutex.lock();
    }

  private:
    MutexType& mutex;

    unlock_guard(const unlock_guard&) = delete;
    unlock_guard& operator=(const unlock_guard&) = delete;
};

};  // namespace Util
};  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_UTIL_H
