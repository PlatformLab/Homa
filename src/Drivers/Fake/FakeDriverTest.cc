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

#include "FakeDriver.h"
#include "StringUtil.h"

#include "../RawAddressType.h"

#include <string>

namespace Homa {
namespace Drivers {
namespace Fake {
namespace {

TEST(FakeDriverTest, constructor)
{
    uint64_t nextAddressId = FakeDriver().localAddressId + 1;

    FakeDriver driver;
    EXPECT_EQ(nextAddressId, driver.localAddressId);
}

TEST(FakeDriverTest, getAddress_string)
{
    FakeDriver driver;
    std::string addressStr("42");
    Driver::Address* address = driver.getAddress(&addressStr);
    EXPECT_EQ("42", address->toString());
}

TEST(FakeDriverTest, getAddress_raw)
{
    FakeDriver driver;
    Driver::Address::Raw raw;
    raw.type = RawAddressType::FAKE;
    *reinterpret_cast<uint64_t*>(raw.bytes) = 42;
    Driver::Address* address = driver.getAddress(&raw);
    EXPECT_EQ("42", address->toString());
}

TEST(FakeDriverTest, allocPacket)
{
    FakeDriver driver;
    Driver::Packet* packet = driver.allocPacket();
    // allocPacket doesn't do much so we just need to make sure we can call it.
    delete packet;
}

TEST(FakeDriverTest, sendPackets)
{
    FakeDriver driver1;
    FakeDriver driver2;

    Driver::Packet* packets[4];
    for (int i = 0; i < 4; ++i) {
        packets[i] = driver1.allocPacket();
        packets[i]->address = driver2.getLocalAddress();
        packets[i]->priority = i;
    }
    std::string addressStr("42");
    packets[2]->address = driver1.getAddress(&addressStr);

    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(1).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(3).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(4).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(7).size());

    driver1.sendPackets(packets, 1);

    EXPECT_EQ(1U, driver2.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(1).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(3).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(4).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(7).size());
    {
        Driver::Packet* packet = static_cast<Driver::Packet*>(
            driver2.nic.priorityQueue.at(0).front());
        EXPECT_EQ(driver1.getLocalAddress(), packet->address);
    }

    driver1.sendPackets(packets, 4);

    EXPECT_EQ(2U, driver2.nic.priorityQueue.at(0).size());
    EXPECT_EQ(1U, driver2.nic.priorityQueue.at(1).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(2).size());
    EXPECT_EQ(1U, driver2.nic.priorityQueue.at(3).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(4).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(7).size());

    delete packets[2];
}

TEST(FakeDriverTest, receivePackets)
{
    std::string addressStr("42");
    FakeDriver driver;

    Driver::Packet* packets[4];

    // 3 packets at priority 7
    for (int i = 0; i < 3; ++i)
        driver.nic.priorityQueue.at(7).push_back(new FakePacket);
    // 3 packets at priority 5
    for (int i = 0; i < 3; ++i)
        driver.nic.priorityQueue.at(5).push_back(new FakePacket);
    // 1 packet at priority 4
    driver.nic.priorityQueue.at(4).push_back(new FakePacket);
    // 1 packet at priority 2
    driver.nic.priorityQueue.at(2).push_back(new FakePacket);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(3U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(3U, driver.nic.priorityQueue.at(7).size());

    EXPECT_EQ(4U, driver.receivePackets(4, packets));
    driver.releasePackets(packets, 4);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(2U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(7).size());

    EXPECT_EQ(1U, driver.receivePackets(1, packets));
    driver.releasePackets(packets, 1);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(7).size());

    driver.nic.priorityQueue.at(7).push_back(new FakePacket);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(7).size());

    EXPECT_EQ(1U, driver.receivePackets(1, packets));
    driver.releasePackets(packets, 1);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(7).size());

    EXPECT_EQ(3U, driver.receivePackets(4, packets));
    driver.releasePackets(packets, 3);
}

TEST(FakeDriverTest, releasePackets)
{
    // releasePackets is well testing in receivePackets test.
}

TEST(FakeDriverTest, getHighestPacketPriority)
{
    FakeDriver driver;
    EXPECT_EQ(7, driver.getHighestPacketPriority());
}

TEST(FakeDriverTest, getMaxPayloadSize)
{
    FakeDriver driver;
    EXPECT_EQ(MAX_PAYLOAD_SIZE, driver.getMaxPayloadSize());
}

TEST(FakeDriverTest, getBandwidth)
{
    FakeDriver driver;
    EXPECT_EQ(0U, driver.getBandwidth());
}

TEST(FakeDriverTest, getLocalAddress)
{
    uint64_t nextAddressId = FakeDriver().localAddressId + 1;
    std::string addressStr = StringUtil::format("%lu", nextAddressId);

    FakeDriver driver;
    EXPECT_EQ(driver.getAddress(&addressStr), driver.getLocalAddress());
}

}  // namespace
}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa