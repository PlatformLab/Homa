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

#ifndef HOMA_INCLUDE_HOMA_EXCEPTION_H
#define HOMA_INCLUDE_HOMA_EXCEPTION_H

#include "Homa/Util.h"

#include <cxxabi.h>
#include <cstring>
#include <exception>
#include <memory>
#include <string>

namespace Homa {

/**
 * The base class for all Homa exceptions.
 */
struct Exception : public std::exception {
    explicit Exception(const std::string& where)
        : message("")
        , errNo(0)
        , where(where)
        , whatCache()
    {}
    Exception(const std::string& where, std::string msg)
        : message(msg)
        , errNo(0)
        , where(where)
        , whatCache()
    {}
    Exception(const std::string& where, int errNo)
        : message("")
        , errNo(errNo)
        , where(where)
        , whatCache()
    {
        message = std::strerror(errNo);
    }
    Exception(const std::string& where, std::string msg, int errNo)
        : message(msg + ": " + std::strerror(errNo))
        , errNo(errNo)
        , where(where)
        , whatCache()
    {}
    Exception(const Exception& other)
        : message(other.message)
        , errNo(other.errNo)
        , where(other.where)
        , whatCache()
    {}
    virtual ~Exception() throw() {}
    std::string str() const
    {
        return (Util::demangle(typeid(*this).name()) + ": " + message +
                ", thrown at " + where);
    }
    const char* what() const throw()
    {
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
    std::string where;

  private:
    mutable std::unique_ptr<const char[]> whatCache;
};

/**
 * A fatal error that should exit the program.
 */
struct FatalError : public Exception {
    explicit FatalError(const std::string& where)
        : Exception(where)
    {}
    FatalError(const std::string& where, std::string msg)
        : Exception(where, msg)
    {}
    FatalError(const std::string& where, int errNo)
        : Exception(where, errNo)
    {}
    FatalError(const std::string& where, std::string msg, int errNo)
        : Exception(where, msg, errNo)
    {}
};

}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_EXCEPTION_H
