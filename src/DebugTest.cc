/* Copyright (c) 2012-2018 Stanford University
 * Copyright (c) 2014-2015 Diego Ongaro
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

#include <gtest/gtest.h>

#include "Debug.h"

#include "STLUtil.h"

#include <sys/stat.h>
#include <unordered_map>

namespace Homa {
namespace Debug {

namespace Internal {
extern std::unordered_map<const char*, LogLevel> isLoggingCache;
const char* logLevelToString(LogLevel);
LogLevel logLevelFromString(const std::string& level);
LogLevel getLogLevel(const char* fileName);
const char* relativeFileName(const char* fileName);
}  // namespace Internal

namespace {

class DebugTest : public ::testing::Test {
  public:
    DebugTest()
    {
        setLogPolicy({});
        setLogFile(stderr);
    }
    ~DebugTest()
    {
        Debug::setLogHandler(std::function<void(DebugMessage)>());
        FILE* prev = setLogFile(stderr);
        if (prev != stderr)
            fclose(prev);
    }
};

TEST_F(DebugTest, logLevelToString)
{
    EXPECT_STREQ("SILENT", Internal::logLevelToString(LogLevel::SILENT));
    EXPECT_STREQ("ERROR", Internal::logLevelToString(LogLevel::ERROR));
    EXPECT_STREQ("WARNING", Internal::logLevelToString(LogLevel::WARNING));
    EXPECT_STREQ("NOTICE", Internal::logLevelToString(LogLevel::NOTICE));
    EXPECT_STREQ("VERBOSE", Internal::logLevelToString(LogLevel::VERBOSE));
}

TEST_F(DebugTest, logLevelFromString)
{
    EXPECT_EQ(LogLevel::SILENT, Internal::logLevelFromString("SILeNT"));
    EXPECT_EQ(LogLevel::ERROR, Internal::logLevelFromString("ERrOR"));
    EXPECT_EQ(LogLevel::WARNING, Internal::logLevelFromString("WARNiNG"));
    EXPECT_EQ(LogLevel::NOTICE, Internal::logLevelFromString("NOTIcE"));
    EXPECT_EQ(LogLevel::VERBOSE, Internal::logLevelFromString("VERBOsE"));
    EXPECT_DEATH(Internal::logLevelFromString("asdlf"),
                 "'asdlf' is not a valid log level.");
}

TEST_F(DebugTest, getLogLevel)
{
    // verify default is NOTICE
    EXPECT_EQ(LogLevel::NOTICE, Internal::getLogLevel(__FILE__));

    setLogPolicy({{"prefix", "VERBOSE"}, {"suffix", "ERROR"}, {"", "WARNING"}});
    EXPECT_EQ(LogLevel::VERBOSE, Internal::getLogLevel("prefixabcsuffix"));
    EXPECT_EQ(LogLevel::ERROR, Internal::getLogLevel("abcsuffix"));
    EXPECT_EQ(LogLevel::WARNING, Internal::getLogLevel("asdf"));
}

TEST_F(DebugTest, relativeFileName)
{
    EXPECT_STREQ("src/DebugTest.cc", Internal::relativeFileName(__FILE__));
    EXPECT_STREQ("/a/b/c", Internal::relativeFileName("/a/b/c"));
}

TEST_F(DebugTest, isLogging)
{
    EXPECT_TRUE(isLogging(LogLevel::ERROR, "abc"));
    EXPECT_TRUE(isLogging(LogLevel::ERROR, "abc"));
    EXPECT_FALSE(isLogging(LogLevel::VERBOSE, "abc"));
    EXPECT_EQ((std::vector<std::pair<const char*, LogLevel>>{
                  {"abc", LogLevel::NOTICE},
              }),
              STLUtil::getItems(Internal::isLoggingCache));
}

TEST_F(DebugTest, setLogFile)
{
    EXPECT_EQ(stderr, setLogFile(stdout));
    EXPECT_EQ(stdout, setLogFile(stderr));
}

struct VectorHandler {
    VectorHandler()
        : messages()
    {}
    void operator()(DebugMessage message)
    {
        messages.push_back(message);
    }
    std::vector<DebugMessage> messages;
};

TEST_F(DebugTest, setLogHandler)
{
    VectorHandler handler;
    setLogHandler(std::ref(handler));
    ERROR("Hello, world! %d", 9);
    EXPECT_EQ(1U, handler.messages.size());
    const DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/DebugTest.cc", m.filename);
    EXPECT_LT(1, m.linenum);
    EXPECT_STREQ("TestBody", m.function);
    EXPECT_EQ(int(LogLevel::ERROR), m.logLevel);
    EXPECT_STREQ("ERROR", m.logLevelString);
    EXPECT_EQ("Hello, world! 9", m.message);
}

TEST_F(DebugTest, setLogPolicy)
{
    setLogPolicy({{"prefix", "VERBOSE"}, {"suffix", "ERROR"}, {"", "WARNING"}});
    EXPECT_EQ(LogLevel::VERBOSE, Internal::getLogLevel("prefixabcsuffix"));
    EXPECT_EQ(LogLevel::ERROR, Internal::getLogLevel("abcsuffix"));
    EXPECT_EQ(LogLevel::WARNING, Internal::getLogLevel("asdf"));
}

std::string
normalize(const std::string& in)
{
    return logPolicyToString(logPolicyFromString(in));
}

TEST_F(DebugTest, logPolicyFromString)
{
    EXPECT_EQ("NOTICE", normalize(""));
    EXPECT_EQ("ERROR", normalize("ERROR"));
    EXPECT_EQ("ERROR", normalize("@ERROR"));
    EXPECT_EQ("prefix@VERBOSE,suffix@ERROR,WARNING",
              normalize("prefix@VERBOSE,suffix@ERROR,WARNING"));
    EXPECT_EQ("prefix@VERBOSE,suffix@ERROR,NOTICE",
              normalize("prefix@VERBOSE,suffix@ERROR,@NOTICE"));
    EXPECT_EQ("prefix@VERBOSE,suffix@ERROR,NOTICE",
              normalize("prefix@VERBOSE,suffix@ERROR,NOTICE"));
}

TEST_F(DebugTest, logPolicyToString)
{
    EXPECT_EQ("NOTICE", logPolicyToString(getLogPolicy()));
    setLogPolicy({{"", "ERROR"}});
    EXPECT_EQ("ERROR", logPolicyToString(getLogPolicy()));
    setLogPolicy({{"prefix", "VERBOSE"}, {"suffix", "ERROR"}, {"", "WARNING"}});
    EXPECT_EQ("prefix@VERBOSE,suffix@ERROR,WARNING",
              logPolicyToString(getLogPolicy()));
    setLogPolicy({{"prefix", "VERBOSE"}, {"suffix", "ERROR"}});
    EXPECT_EQ("prefix@VERBOSE,suffix@ERROR,NOTICE",
              logPolicyToString(getLogPolicy()));
}

// log: low cost-benefit in testing

}  // namespace
}  // namespace Debug
}  // namespace Homa
