/* Copyright (c) 2018-2020, Stanford University
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

#include <Homa/Debug.h>
#include <gtest/gtest.h>

#include "Homa/Utils/TransportPoller.h"
#include "Mock/MockDriver.h"
#include "Mock/MockReceiver.h"
#include "Mock/MockSender.h"
#include "Protocol.h"
#include "TransportImpl.h"
#include "Tub.h"

namespace Homa {
namespace Core {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArrayArgument;

/**
 * Defines a matcher EqPacket(p) to match two Driver::Packet* by their
 * underlying packet buffer descriptors.
 */
MATCHER_P(EqPacket, p, "")
{
    return arg->descriptor == p->descriptor;
}

class TransportImplTest : public ::testing::Test {
  public:
    TransportImplTest()
        : mockDriver(allocMockDriver())
        , mockSender(new NiceMock<Homa::Mock::MockSender>(22, mockDriver, 0, 0))
        , mockReceiver(new NiceMock<Homa::Mock::MockReceiver>(mockDriver, 0, 0))
        , transport(new TransportImpl(mockDriver, nullptr, mockSender,
                                      mockReceiver, 22))
        , poller(transport)
    {
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~TransportImplTest()
    {
        delete transport;
        delete mockDriver;
        PerfUtils::Cycles::mockTscValue = 0;
    }

    NiceMock<Homa::Mock::MockDriver>* allocMockDriver()
    {
        auto driver = new NiceMock<Homa::Mock::MockDriver>();
        ON_CALL(*driver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(*driver, getMaxPayloadSize).WillByDefault(Return(1024));
        return driver;
    }

    NiceMock<Homa::Mock::MockDriver>* mockDriver;
    NiceMock<Homa::Mock::MockSender>* mockSender;
    NiceMock<Homa::Mock::MockReceiver>* mockReceiver;
    TransportImpl* transport;
    TransportPoller poller;
};

TEST_F(TransportImplTest, poll)
{
    EXPECT_CALL(*mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, trySend).Times(1);
    EXPECT_CALL(*mockReceiver, trySendGrants).Times(1);
    EXPECT_CALL(*mockSender, checkTimeouts).WillOnce(Return(10000));
    EXPECT_CALL(*mockReceiver, checkTimeouts).WillOnce(Return(10100));

    poller.poll();

    EXPECT_EQ(10000U, poller.nextTimeoutCycles);

    EXPECT_CALL(*mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, trySend).Times(1);
    EXPECT_CALL(*mockReceiver, trySendGrants).Times(1);
    EXPECT_CALL(*mockSender, checkTimeouts).WillOnce(Return(10200));
    EXPECT_CALL(*mockReceiver, checkTimeouts).WillOnce(Return(10100));

    poller.poll();

    EXPECT_EQ(10100U, poller.nextTimeoutCycles);

    EXPECT_CALL(*mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, trySend).Times(1);
    EXPECT_CALL(*mockReceiver, trySendGrants).Times(1);
    EXPECT_CALL(*mockSender, checkTimeouts).Times(0);
    EXPECT_CALL(*mockReceiver, checkTimeouts).Times(0);

    poller.poll();

    EXPECT_EQ(10100U, poller.nextTimeoutCycles);
}

TEST_F(TransportImplTest, processPackets)
{
    char payload[8][1024];
    Homa::Driver::Packet packets[8];

    // Set DATA packet
    Homa::Mock::MockDriver::PacketBuf dataPacketBuf{payload[0]};
    Driver::Packet dataPacket = dataPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::DataHeader*>(dataPacket.payload)
        ->common.opcode = Protocol::Packet::DATA;
    packets[0] = dataPacket;
    EXPECT_CALL(*mockReceiver, handleDataPacket(EqPacket(&packets[0]), _));

    // Set GRANT packet
    Homa::Mock::MockDriver::PacketBuf grantPacketBuf{payload[1]};
    Driver::Packet grantPacket = grantPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::GrantHeader*>(grantPacket.payload)
        ->common.opcode = Protocol::Packet::GRANT;
    packets[1] = grantPacket;
    EXPECT_CALL(*mockSender, handleGrantPacket(EqPacket(&packets[1])));

    // Set DONE packet
    Homa::Mock::MockDriver::PacketBuf donePacketBuf{payload[2]};
    Driver::Packet donePacket = donePacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::DoneHeader*>(donePacket.payload)
        ->common.opcode = Protocol::Packet::DONE;
    packets[2] = donePacket;
    EXPECT_CALL(*mockSender, handleDonePacket(EqPacket(&packets[2])));

    // Set RESEND packet
    Homa::Mock::MockDriver::PacketBuf resendPacketBuf{payload[3]};
    Driver::Packet resendPacket = resendPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::ResendHeader*>(resendPacket.payload)
        ->common.opcode = Protocol::Packet::RESEND;
    packets[3] = resendPacket;
    EXPECT_CALL(*mockSender, handleResendPacket(EqPacket(&packets[3])));

    // Set BUSY packet
    Homa::Mock::MockDriver::PacketBuf busyPacketBuf{payload[4]};
    Driver::Packet busyPacket = busyPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::PingHeader*>(busyPacket.payload)
        ->common.opcode = Protocol::Packet::BUSY;
    packets[4] = busyPacket;
    EXPECT_CALL(*mockReceiver, handleBusyPacket(EqPacket(&packets[4])));

    // Set PING packet
    Homa::Mock::MockDriver::PacketBuf pingPacketBuf{payload[5]};
    Driver::Packet pingPacket = pingPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::PingHeader*>(pingPacket.payload)
        ->common.opcode = Protocol::Packet::PING;
    packets[5] = pingPacket;
    EXPECT_CALL(*mockReceiver, handlePingPacket(EqPacket(&packets[5]), _));

    // Set UNKNOWN packet
    Homa::Mock::MockDriver::PacketBuf unknownPacketBuf{payload[6]};
    Driver::Packet unknownPacket = unknownPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::UnknownHeader*>(unknownPacket.payload)
        ->common.opcode = Protocol::Packet::UNKNOWN;
    packets[6] = unknownPacket;
    EXPECT_CALL(*mockSender, handleUnknownPacket(EqPacket(&packets[6])));

    // Set ERROR packet
    Homa::Mock::MockDriver::PacketBuf errorPacketBuf{payload[7]};
    Driver::Packet errorPacket = errorPacketBuf.toPacket(1024);
    static_cast<Protocol::Packet::ErrorHeader*>(errorPacket.payload)
        ->common.opcode = Protocol::Packet::ERROR;
    packets[7] = errorPacket;
    EXPECT_CALL(*mockSender, handleErrorPacket(EqPacket(&packets[7])));

    EXPECT_CALL(*mockDriver, receivePackets)
        .WillOnce(DoAll(SetArrayArgument<1>(packets, packets + 8), Return(8)));

    poller.processPackets();
}

}  // namespace
}  // namespace Core
}  // namespace Homa
