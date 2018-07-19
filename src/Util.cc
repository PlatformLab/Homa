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

#include "Util.h"

#include "Exception.h"

namespace Homa {
namespace Util {

/**
 * Helper function to call __cxa_demangle. Has internal linkage.
 * Handles the C-style memory management required.
 * Returns a std::string with the long human-readable name of the
 * type.
 * @param name
 *      The "name" of the type that needs to be demangled.
 * @throw FatalError
 *      The short internal type name could not be converted.
 */
// This was taken from the RAMCloud project.
std::string
demangle(const char* name)
{
    int status;
    char* res = abi::__cxa_demangle(name, NULL, NULL, &status);
    if (status != 0) {
        throw FatalError(HERE, "cxxabi.h's demangle() could not demangle type");
    }
    // contruct a string with a copy of the C-style string returned.
    std::string ret(res);
    // __cxa_demangle would have used realloc() to allocate memory
    // which should be freed now.
    free(res);
    return ret;
}

/**
 * A safe version of sprintf.
 */
// This was taken from the RAMCloud project.
std::string
format(const char* format, ...)
{
    std::string s;
    va_list ap;
    va_start(ap, format);

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

    va_end(ap);
    return s;
}

}  // namespace Util
}  // namespace Homa
