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

#include "CodeLocation.h"

#include <gtest/gtest.h>

namespace Homa {

TEST(CodeLocationTest, str)
{
    CodeLocation where("src/FOO.cc", 42, "bar", "void FOO::bar(int i)");
    EXPECT_EQ("FOO::bar at src/FOO.cc:42", where.str());
}

TEST(CodeLocationTest, baseFileName)
{
    CodeLocation where("src/FOO.cc", 42, "bar", "void FOO::bar(int i)");
    EXPECT_STREQ("FOO.cc", where.baseFileName());
}

TEST(CodeLocationTest, relativeFile)
{
    CodeLocation where = HERE;
    EXPECT_EQ("src/CodeLocationTest.cc", where.relativeFile());

    where.file = "CodeLocationTest.cc";
    EXPECT_EQ(where.file, where.relativeFile());

    where.file = "/strange/path/to/ramcloud/src/CodeLocationTest.cc";
    EXPECT_EQ(where.file, where.relativeFile());
}

TEST(CodeLocationTest, qualifiedFunction)
{
    CodeLocation where("", 0, "", "");

    where.function = "func";
    where.prettyFunction = "std::string func()";
    EXPECT_EQ("func", where.qualifiedFunction());

    where.function = "func";
    where.prettyFunction = "std::string Homa::CodeLocationTest::func()";
    EXPECT_EQ("Homa::CodeLocationTest::func", where.qualifiedFunction());

    where.function = "func";
    where.prettyFunction =
        "std::string Homa::CodeLocationTest::func("
        "const Homa::CodeLocation&) const";
    EXPECT_EQ("Homa::CodeLocationTest::func", where.qualifiedFunction());

    where.function = "func";
    where.prettyFunction =
        "static std::string Homa::CodeLocationTest::func("
        "const Homa::CodeLocation&)";
    EXPECT_EQ("Homa::CodeLocationTest::func", where.qualifiedFunction());

    where.function = "func";
    where.prettyFunction = "void Homa::func(void (*)(int))";
    EXPECT_EQ("Homa::func", where.qualifiedFunction());

    where.prettyFunction = "void (* Homa::func())(int)";
    EXPECT_EQ("Homa::func", where.qualifiedFunction());

    where.prettyFunction = "void (* Homa::func(void (*)(int)))(int)";
    EXPECT_EQ("Homa::func", where.qualifiedFunction());

    where.prettyFunction =
        "void (* (* Homa::func(void (* (*)(void (*)"
        "(int), void (*)(int)))(int), void (* (*)(void (*)"
        "(int), void (*)(int)))(int)))(void (*)(int), void "
        "(*)(int)))(int)";
    EXPECT_EQ("Homa::func", where.qualifiedFunction());
}

}  // namespace Homa