/* Copyright (c) 2011-2018, Stanford University
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

#include "CodeLocation.h"

#include "StringUtil.h"

#include "Homa/Util.h"

#include <regex>

namespace Homa {

namespace {

/**
 * Return the number of characters of __FILE__ that make up the path prefix.
 * That is, __FILE__ plus this value will be the relative path from the top
 * directory of project repo.
 */
int
length__FILE__Prefix()
{
    const char* start = __FILE__;
    const char* match = strstr(__FILE__, "src/CodeLocation.cc");
    assert(match != NULL);
    return Util::downCast<int>(match - start);
}

}  // anonymous namespace

/**
 * Return a string representation of the current location in the code.
 */
std::string
CodeLocation::str() const
{
    return StringUtil::format("%s at %s:%d", qualifiedFunction().c_str(),
                              relativeFile().c_str(), line);
}

/**
 * Return the base name of the file (i.e., only the last component of the
 * file name, omitting any preceding directories).
 */
const char*
CodeLocation::baseFileName() const
{
    const char* lastSlash = strrchr(file, '/');
    if (lastSlash == NULL) {
        return file;
    }
    return lastSlash + 1;
}

std::string
CodeLocation::relativeFile() const
{
    static int lengthFilePrefix = length__FILE__Prefix();
    // Remove the prefix only if it matches that of __FILE__. This check is
    // needed in case someone compiles different files using different paths.
    if (strncmp(file, __FILE__, lengthFilePrefix) == 0)
        return std::string(file + lengthFilePrefix);
    else
        return std::string(file);
}

/**
 * Return the name of the function, qualified by its surrounding classes and
 * namespaces.
 *
 * Beware: the original version of this method imported from the RAMCloud
 * project used PCRECPP, was really really slow (10-20 microseconds) and was
 * thus NOT used in log messages. The current implemenation uses C++11 regex but
 * may not be much faster.
 */
std::string
CodeLocation::qualifiedFunction() const
{
    std::smatch matches;
    const std::string pattern(
        StringUtil::format("\\s(\\S*\\b%s)\\(", function));
    std::string prettyFunctionStr = prettyFunction;
    std::regex re(pattern);
    std::regex_search(prettyFunctionStr, matches, re);

    // Expect at least one match; matches[1] is the 1st captured sub-expression.
    if (!matches.empty() && matches[1].matched) {
        return matches[1];
    } else {
        // shouldn't happen
        return function;
    }
}

}  // namespace Homa
