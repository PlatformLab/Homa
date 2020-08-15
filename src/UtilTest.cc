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

#include <Homa/Util.h>
#include <gtest/gtest.h>

namespace Homa {

TEST(UtilTest, arrayLength)
{
    int nums[] = {1, 2, 3, 4, 5};
    EXPECT_EQ(5U, Util::arrayLength(nums));
}

TEST(UtilTest, downCast)
{
    char c;
    long int l = 64;
    c = Util::downCast<char, long int>(l);
    EXPECT_EQ(64, c);
}

TEST(UtilTest, isPowerOfTwo)
{
    EXPECT_TRUE(Util::isPowerOfTwo(4));
    EXPECT_FALSE(Util::isPowerOfTwo(3));
}

}  // namespace Homa