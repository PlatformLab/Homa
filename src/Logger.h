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

#ifndef HOMA_LOGGER_H
#define HOMA_LOGGER_H

#include "CodeLocation.h"
#include "SpinLock.h"

namespace Homa {

/**
 * Used to inidicate the level of verbosity of the Logger's output and the level
 * at which a particular log message should be outputed. The LogLevel enum
 * should be kept in sync with the logLevelNames.
 */
enum LogLevel {
    /**
     * LogLevel::SILENT indicates that no logs should be output by the Logger;
     * no messages should be logged at this level.
     */
    SILENT = 0,

    /**
     * Message at LogLevel::ERROR indicate that something bad has happend. In
     * general, ERROR logs shouldn't happen; it means the system broke some
     * contract with the  users in some way or some major assumption was
     * violated.
     */
    ERROR,

    /**
     * Messages at LogLevel::WARNING indicate that, although something went
     * wrong or something unexpected happened, it was transient and recoverable.
     */
    WARNING,

    /**
     * Messages at LogLevel::NOTICE inidcate normal operation but provide
     * particular notable or useful information for system administration (e.g.
     * initialization information, configuration changes, etc.).
     */
    NOTICE,

    /**
     * Messages at LogLevel::DEBUG don't necessarily indicate that anything
     * went wrong, but they could be useful in diagnosing problems.
     */
    DEBUG,
    NUM_LOG_LEVELS  // must be the last element in the enum
};

/**
 * This class is used to print informational and error messages to stderr. For
 * the most part, callers should use the LOG macro to generate log messages.
 * Configuration changes, however, will require directly accessing this class.
 *
 * This class is thread-safe.
 */
class Logger {
  private:
    explicit Logger(LogLevel level = WARNING);

  public:
    ~Logger();
    static Logger& get();
    void setLogLevel(LogLevel level);

    void logMessage(LogLevel level, const CodeLocation& where,
                    const char* format, ...)
        __attribute__((format(printf, 4, 5)));

    /**
     * Return whether the current logging configuration includes messages of
     * the given level. This is separate from LOG in case there's some
     * non-trivial work that goes into calculating a log message, and it's not
     * possible or convenient to include that work as an expression in the
     * argument list to LOG.
     */
    bool isLogging(LogLevel level)
    {
        return (level <= logLevel);
    }

  private:
    /// Monitor lock to provide thread-safety.
    SpinLock lock;

    /**
     * The current LogLevel at which the Logger should output logs.
     */
    LogLevel logLevel;

    // DISALLOW_COPY_AND_ASSIGN(Logger)
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};

/**
 * Log a message for the system administrator.
 *
 * @param level
 *      The level of importance of the message (LogLevel).
 * @param format
 *      A printf-style format string for the message. It should not have a line
 *      break at the end, as LOG will add one.
 * @param ...
 *      The arguments to the format string.
 */
#define LOG(level, format, ...)                                          \
    do {                                                                 \
        Homa::Logger& _logger = Logger::get();                           \
        if (_logger.isLogging(level)) {                                  \
            _logger.logMessage(level, HERE, format "\n", ##__VA_ARGS__); \
        }                                                                \
    } while (0)

}  // namespace Homa

#endif  // HOMA_LOGGER_H