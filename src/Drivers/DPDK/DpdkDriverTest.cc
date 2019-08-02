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

#include "DpdkDriverImpl.h"

#include <Homa/Debug.h>

namespace Homa {
namespace Drivers {
namespace DPDK {
namespace {

class DpdkDriverImplTest : public ::testing::Test {
  public:
    DpdkDriverImplTest()
        : driver(new DpdkDriverImpl(42))
        , savedLogPolicy(Debug::getLogPolicy())
    {
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~DpdkDriverImplTest()
    {
        delete driver;
        Debug::setLogPolicy(savedLogPolicy);
    }

    DpdkDriverImpl* driver;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(DpdkDriverImplTest, getAddress)
{
    std::string addressString("de:ad:be:ef:98:76");
    EXPECT_TRUE(driver->addressCache.empty());
    Driver::Address* addr = driver->getAddress(&addressString);
    EXPECT_EQ(1U, driver->addressCache.size());
    EXPECT_EQ(addr, driver->getAddress(&addressString));
    EXPECT_EQ(1U, driver->addressCache.size());
}

}  // namespace
}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa
