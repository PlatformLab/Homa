/* Copyright (c) 2019, Stanford University
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

#include <gtest/gtest.h>

#include "FakeAddress.h"

namespace Homa {
namespace Drivers {
namespace Fake {
namespace {

TEST(FakeAddressTest, constructor_id)
{
    FakeAddress address(42);
    EXPECT_EQ("42", address.toString());
}

TEST(FakeAddressTest, constructor_str)
{
    FakeAddress address("42");
    EXPECT_EQ("42", address.toString());
}

TEST(FakeAddressTest, constructor_str_bad)
{
    EXPECT_THROW(FakeAddress address("D42"), BadAddress);
}

TEST(FakeAddressTest, toString)
{
    // tested sufficiently in constructor tests
}

TEST(FakeAddressTest, toAddressId)
{
    EXPECT_THROW(FakeAddress::toAddressId("D42"), BadAddress);
}

}  // namespace
}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa
