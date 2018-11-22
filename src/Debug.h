/* Copyright (c) 2010-2018 Stanford University
 * Copyright (c) 2014 Diego Ongaro
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "StringUtil.h"

#include <cinttypes>
#include <cstdlib>
#include <string>

#include "Homa/Debug.h"

#ifndef HOMA_DEBUG_H
#define HOMA_DEBUG_H

namespace Homa {
namespace Debug {

// Configuring logging is exposed to applications so that stuff goes in a public
// header file: "Homa/Debug.h"

std::ostream& operator<<(std::ostream& ostream, LogLevel level);

bool isLogging(LogLevel level, const char* fileName);

void log(LogLevel level, const char* fileName, uint32_t lineNum,
         const char* functionName, const char* message);

/**
 * A short name to be used in log messages to identify this process.
 * This defaults to the UNIX process ID.
 */
extern std::string processName;

}  // namespace Debug
}  // namespace Homa

/**
 * Unconditionally log the given message to stderr.
 * This is normally called by ERROR(), WARNING(), NOTICE(), or VERBOSE().
 * @param level
 *      The level of importance of the message.
 * @param _format
 *      A printf-style format string for the message. It should not include a
 *      line break at the end, as LOG will add one.
 * @param ...
 *      The arguments to the format string, as in printf.
 */
#define LOG(level, _format, ...)                                             \
    do {                                                                     \
        if (::Homa::Debug::isLogging(level, __FILE__)) {                     \
            ::Homa::Debug::log(                                              \
                level, __FILE__, __LINE__, __FUNCTION__,                     \
                ::Homa::StringUtil::format(_format, ##__VA_ARGS__).c_str()); \
        }                                                                    \
    } while (0)

/**
 * Log an ERROR message and abort the process.
 * @copydetails ERROR
 */
#define PANIC(format, ...)                          \
    do {                                            \
        ERROR(format " Exiting...", ##__VA_ARGS__); \
        ::abort();                                  \
    } while (0)

/**
 * Log an ERROR message and exit the process with status 1.
 * @copydetails ERROR
 */
#define EXIT(format, ...)                           \
    do {                                            \
        ERROR(format " Exiting...", ##__VA_ARGS__); \
        ::exit(1);                                  \
    } while (0)

/**
 * Log an ERROR message.
 * @param format
 *      A printf-style format string for the message. It should not include a
 *      line break at the end, as LOG will add one.
 * @param ...
 *      The arguments to the format string, as in printf.
 */
#define ERROR(format, ...) \
    LOG((::Homa::Debug::LogLevel::ERROR), format, ##__VA_ARGS__)

/**
 * Log a WARNING message.
 * @copydetails ERROR
 */
#define WARNING(format, ...) \
    LOG((::Homa::Debug::LogLevel::WARNING), format, ##__VA_ARGS__)

/**
 * Log a NOTICE message.
 * @copydetails ERROR
 */
#define NOTICE(format, ...) \
    LOG((::Homa::Debug::LogLevel::NOTICE), format, ##__VA_ARGS__)

/**
 * Log a VERBOSE message.
 * @copydetails ERROR
 */
#define VERBOSE(format, ...) \
    LOG((::Homa::Debug::LogLevel::VERBOSE), format, ##__VA_ARGS__)

#endif /* HOMA_DEBUG_H */
