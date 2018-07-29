/* Copyright (c) 2009-2018, Stanford University
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

#ifndef HOMA_UTIL_H
#define HOMA_UTIL_H

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <string>

namespace Homa {
namespace Util {

/// Return the number of elements in a statically allocated array.
// This was taken from the RAMCloud project.
template <typename T, size_t length>
constexpr uint32_t
arrayLength(const T (&array)[length])
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

std::string format(const char* format, ...)
    __attribute__((format(printf, 1, 2)));

std::string hexDump(const void* buf, uint64_t bytes);

};  // namespace Util
};  // namespace Homa

#endif  // HOMA_UTIL_H