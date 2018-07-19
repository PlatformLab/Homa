/* Copyright (c) 2010-2018, Stanford University
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

#include "Logger.h"

#include "ThreadId.h"
#include "Util.h"

#include <time.h>
#include <cstdarg>
#include <iostream>
#include <mutex>

namespace Homa {

/**
 * Friendly names for each LogLevel value.
 * Keep this in sync with the LogLevel enum.
 */
static const char* logLevelNames[] = {"(none)", "ERROR", "WARNING", "NOTICE",
                                      "DEBUG"};

static_assert(Util::arrayLength(logLevelNames) == NUM_LOG_LEVELS,
              "logLevelNames size does not match NUM_LOG_LEVELS");

/**
 * Create a new Logger; messages will go to stderr. Should not be called outside
 * this class except during unit testing.
 *
 * @param level
 *      Messages at least as important as _level_ will be logged.
 */
Logger::Logger(LogLevel level)
    : lock()
    , logLevel()
{
    setLogLevel(level);
}

/**
 * Logger destructor.
 */
Logger::~Logger()
{
    std::clog.flush();
}

/**
 * Return the singleton shared instance that is normally used for logging.
 */
Logger&
Logger::get()
{
    // Use static local variable to achieve efficient thread-safe lazy
    // initialization. If multiple threads attempt to initialize sharedLogger
    // concurrently, the initialization is guaranteed to occur exactly once.
    static Logger sharedLogger;
    return sharedLogger;
}

/**
 * Set the log level for this Logger.
 *
 * @param level
 *      Messages at least as important as _level_ will be logged.
 */
void
Logger::setLogLevel(LogLevel level)
{
    std::lock_guard<SpinLock> _(lock);
    logLevel = level;
}

/**
 * Log a message for the system administrator.

 * @param level
 *      See LOG.
 * @param where
 *      The result of HERE.
 * @param format
 *      See LOG except the string should end with a newline character.
 * @param ...
 *      See LOG.
 */
void
Logger::logMessage(LogLevel level, const CodeLocation& where,
                   const char* format, ...)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    std::lock_guard<SpinLock> _(lock);

    static const int MAX_MESSAGE_CHARS = 2000;
    // Extra space for a message about truncated characters, if needed.
    static const int TRUNC_MESSAGE_SPACE = 50;
    char buffer[MAX_MESSAGE_CHARS + TRUNC_MESSAGE_SPACE];
    int spaceLeft = MAX_MESSAGE_CHARS;
    int charsLost = 0;
    int charsWritten = 0;
    int actual;

    // Create the new log message in a local buffer. First write a standard
    // prefix containing timestamp, information about source file, etc.
    actual = snprintf(buffer + charsWritten, spaceLeft,
                      "%010lu.%09lu %s:%d in %s %s[%d]: ", now.tv_sec,
                      now.tv_nsec, where.baseFileName(), where.line,
                      where.function, logLevelNames[level], ThreadId::get());
    if (actual >= spaceLeft) {
        // We ran out of space in the buffer (should never happen here).
        charsLost += 1 + actual - spaceLeft;
        actual = spaceLeft - 1;
    }
    charsWritten += actual;
    spaceLeft -= actual;

    // Next, add the caller's log message.
    va_list ap;
    va_start(ap, format);
    actual = vsnprintf(buffer + charsWritten, spaceLeft, format, ap);
    va_end(ap);
    if (actual >= spaceLeft) {
        // We ran out of space in the buffer.
        charsLost += 1 + actual - spaceLeft;
        actual = spaceLeft - 1;
    }
    charsWritten += actual;
    spaceLeft -= actual;

    if (charsLost > 0) {
        // Ran out of space: add a note about the lost info.
        charsWritten += snprintf(buffer + charsWritten, TRUNC_MESSAGE_SPACE,
                                 "... (%d chars truncated)\n", charsLost);
    }

    // Output log message to standard error.
    std::clog.write(buffer, charsWritten);
}

}  // namespace Homa