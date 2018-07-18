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

namespace Util {

/**
 * Cast one size of int down to another one.
 * Asserts that no precision is lost at runtime.
 */
// This was taken from the RAMCloud project.
template <typename Small, typename Large>
Small
downCast(const Large& large) {
    Small small = static_cast<Small>(large);
    // The following comparison (rather than "large==small") allows
    // this method to convert between signed and unsigned values.
    assert(large - small == 0);
    return small;
}

/**
 * A safe version of vprintf.
 */
// This was taken from the RAMCloud project.
std::string
vformat(const char* format, va_list ap) {
    std::string s;

    // We're not really sure how big of a buffer will be necessary.
    // Try 1K, if not the return value will tell us how much is necessary.
    int bufSize = 1024;
    while (true) {
        char buf[bufSize];
        // vsnprintf trashes the va_list, so copy it first
        va_list aq;
        __va_copy(aq, ap);
        int r = std::vsnprintf(buf, bufSize, format, aq);
        assert(r >= 0);  // old glibc versions returned -1
        if (r < bufSize) {
            s = buf;
            break;
        }
        bufSize = r + 1;
    }

    return s;
}

/**
 * A safe version of sprintf.
 */
// This was taken from the RAMCloud project.
std::string
format(const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    std::string s = vformat(format, ap);
    va_end(ap);
    return s;
}

};  // namespace Util

#endif  // HOMA_UTIL_H