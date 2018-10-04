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

#include "Scheduler.h"

#include "MockDriver.h"

#include <Homa/Debug.h>

namespace Homa {
namespace Core {
namespace {

using ::testing::Eq;
using ::testing::InSequence;
using ::testing::NiceMock;
using ::testing::Return;

class ScheudlerTest : public ::testing::Test {
  public:
    ScheudlerTest()
        : mockDriver()
        , mockPacket(&payload, 0)
        , scheduler()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        scheduler = new Scheduler(&mockDriver);
    }

    ~ScheudlerTest()
    {
        delete scheduler;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    NiceMock<MockDriver::MockPacket> mockPacket;
    char payload[1000];
    Scheduler* scheduler;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(ScheudlerTest, constructor)
{
    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));

    Scheduler scheduler(&mockDriver);
    EXPECT_EQ(&mockDriver, scheduler.driver);
    EXPECT_EQ(5000U, scheduler.RTT_BYTES);
}

TEST_F(ScheudlerTest, packetReceived)
{
    Protocol::MessageId msgId(42, 32);
    Driver::Address* sourceAddr = (Driver::Address*)22;
    uint32_t TOTAL_MESSAGE_LEN = 9000;
    uint32_t TOTAL_BYTES_RECIEVED = 1000;

    InSequence _seq;
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets).Times(1);
    EXPECT_CALL(mockDriver, releasePackets).Times(1);

    scheduler->packetReceived(msgId, sourceAddr, TOTAL_MESSAGE_LEN,
                              TOTAL_BYTES_RECIEVED);

    Protocol::GrantHeader* header = (Protocol::GrantHeader*)payload;
    EXPECT_EQ(msgId, header->common.msgId);
    EXPECT_EQ(6000U, header->offset);
    EXPECT_EQ(sizeof(Protocol::GrantHeader), mockPacket.len);
    EXPECT_EQ(sourceAddr, mockPacket.address);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
