/* Copyright (c) 2018, Stanford University
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

#include "OpContext.h"

namespace Homa {
namespace Core {
namespace {

TEST(OpContextPoolTest, basic)
{
    OpContextPool pool;
    EXPECT_EQ(0U, pool.pool.outstandingObjects);
    OpContext* opContext = pool.construct();
    EXPECT_EQ(1U, pool.pool.outstandingObjects);
    pool.destroy(opContext);
    EXPECT_EQ(0U, pool.pool.outstandingObjects);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
