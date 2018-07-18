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

#ifndef HOMA_EXCEPTION_H
#define HOMA_EXCEPTION_H

#include "CodeLocation.h"

#include <cxxabi.h>
#include <cstring>
#include <exception>
#include <memory>
#include <string>

namespace Homa {

// Forward declaration
std::string demangle(const char* name);

/**
 * The base class for all Homa exceptions.
 */
struct Exception : public std::exception {
    explicit Exception(const CodeLocation& where)
        : message(""), errNo(0), where(where), whatCache() {}
    Exception(const CodeLocation& where, std::string msg)
        : message(msg), errNo(0), where(where), whatCache() {}
    Exception(const CodeLocation& where, int errNo)
        : message(""), errNo(errNo), where(where), whatCache() {
        message = std::strerror(errNo);
    }
    Exception(const CodeLocation& where, std::string msg, int errNo)
        : message(msg + ": " + std::strerror(errNo))
        , errNo(errNo)
        , where(where)
        , whatCache() {}
    Exception(const Exception& other)
        : message(other.message)
        , errNo(other.errNo)
        , where(other.where)
        , whatCache() {}
    virtual ~Exception() throw() {}
    std::string str() const {
        return (demangle(typeid(*this).name()) + ": " + message +
                ", thrown at " + where.str());
    }
    const char* what() const throw() {
        if (whatCache)
            return whatCache.get();
        std::string s(str());
        char* cStr = new char[s.length() + 1];
        whatCache.reset(const_cast<const char*>(cStr));
        memcpy(cStr, s.c_str(), s.length() + 1);
        return cStr;
    }
    std::string message;
    int errNo;
    CodeLocation where;

  private:
    mutable std::unique_ptr<const char[]> whatCache;
};

/**
 * A fatal error that should exit the program.
 */
struct FatalError : public Exception {
    explicit FatalError(const CodeLocation& where) : Exception(where) {}
    FatalError(const CodeLocation& where, std::string msg)
        : Exception(where, msg) {}
    FatalError(const CodeLocation& where, int errNo)
        : Exception(where, errNo) {}
    FatalError(const CodeLocation& where, std::string msg, int errNo)
        : Exception(where, msg, errNo) {}
};

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
demangle(const char* name) {
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

}  // namespace Homa

#endif  // HOMA_EXCEPTION_H
