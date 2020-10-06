/* Copyright (c) 2019-2020, Stanford University
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

#include <Homa/Drivers/Fake/FakeDriver.h>
#include <gtest/gtest.h>

#include <string>

#include "StringUtil.h"

namespace Homa {
namespace Drivers {
namespace Fake {
namespace {

TEST(FakeDriverTest, constructor)
{
    uint32_t nextAddressId = FakeDriver().localAddressId + 1;

    FakeDriver driver;
    EXPECT_EQ(nextAddressId, driver.localAddressId);
}

TEST(FakeDriverTest, allocPacket)
{
    FakeDriver driver;
    Driver::Packet* packet = driver.allocPacket();
    // allocPacket doesn't do much so we just need to make sure we can call it.
    delete container_of(packet, &FakePacket::base);
}

TEST(FakeDriverTest, sendPackets)
{
    FakeDriver driver1;
    FakeDriver driver2;

    Driver::Packet* packets[4];
    IpAddress destinations[4];
    int prio[4];
    for (int i = 0; i < 4; ++i) {
        packets[i] = driver1.allocPacket();
        destinations[i] = driver2.getLocalAddress();
        prio[i] = i;
    }
    destinations[2] = IpAddress{42};

    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(1).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(3).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(4).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(7).size());

    driver1.sendPacket(packets[0], destinations[0], prio[0]);

    EXPECT_EQ(1U, driver2.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(1).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(3).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(4).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(7).size());
    {
        FakePacket* packet = driver2.nic.priorityQueue.at(0).front();
        EXPECT_EQ(driver1.getLocalAddress(), packet->sourceIp);
    }

    for (int i = 0; i < 4; ++i) {
        driver1.sendPacket(packets[i], destinations[i], prio[i]);
    }

    EXPECT_EQ(2U, driver2.nic.priorityQueue.at(0).size());
    EXPECT_EQ(1U, driver2.nic.priorityQueue.at(1).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(2).size());
    EXPECT_EQ(1U, driver2.nic.priorityQueue.at(3).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(4).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver2.nic.priorityQueue.at(7).size());

    delete container_of(packets[2], &FakePacket::base);
}

TEST(FakeDriverTest, receivePackets)
{
    std::string addressStr("42");
    FakeDriver driver;

    Driver::Packet* packets[4];
    IpAddress srcAddrs[4];

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

    EXPECT_EQ(4U, driver.receivePackets(4, packets, srcAddrs));
    driver.releasePackets(packets, 4);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(2U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(7).size());

    EXPECT_EQ(1U, driver.receivePackets(1, packets, srcAddrs));
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

    EXPECT_EQ(1U, driver.receivePackets(1, packets, srcAddrs));
    driver.releasePackets(packets, 1);

    EXPECT_EQ(0U, driver.nic.priorityQueue.at(0).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(1).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(2).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(3).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(4).size());
    EXPECT_EQ(1U, driver.nic.priorityQueue.at(5).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(6).size());
    EXPECT_EQ(0U, driver.nic.priorityQueue.at(7).size());

    EXPECT_EQ(3U, driver.receivePackets(4, packets, srcAddrs));
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
    EXPECT_EQ(10000U, driver.getBandwidth());
}

TEST(FakeDriverTest, getLocalAddress)
{
    uint32_t nextAddressId = FakeDriver().localAddressId + 1;
    FakeDriver driver;
    EXPECT_EQ(nextAddressId, (uint32_t)driver.getLocalAddress());
}

}  // namespace
}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa