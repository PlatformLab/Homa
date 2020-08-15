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

class TransportImplTest : public ::testing::Test {
  public:
    TransportImplTest()
        : mockDriver()
        , transport(new TransportImpl(&mockDriver, 22))
        , mockSender(
              new NiceMock<Homa::Mock::MockSender>(22, &mockDriver, 0, 0))
        , mockReceiver(
              new NiceMock<Homa::Mock::MockReceiver>(&mockDriver, 0, 0))
    {
        transport->sender.reset(mockSender);
        transport->receiver.reset(mockReceiver);
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~TransportImplTest()
    {
        delete transport;
        PerfUtils::Cycles::mockTscValue = 0;
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    TransportImpl* transport;
    NiceMock<Homa::Mock::MockSender>* mockSender;
    NiceMock<Homa::Mock::MockReceiver>* mockReceiver;
};

TEST_F(TransportImplTest, poll)
{
    EXPECT_CALL(mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, poll).Times(1);
    EXPECT_CALL(*mockReceiver, poll).Times(1);

    transport->poll();

    EXPECT_CALL(mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, poll).Times(1);
    EXPECT_CALL(*mockReceiver, poll).Times(1);

    transport->poll();

    EXPECT_CALL(mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, poll).Times(1);
    EXPECT_CALL(*mockReceiver, poll).Times(1);

    transport->poll();
}

TEST_F(TransportImplTest, processPackets)
{
    char payload[8][1024];
    Homa::Driver::Packet* packets[8];

    // Set DATA packet
    Homa::Mock::MockDriver::MockPacket dataPacket{payload[0], 1024};
    static_cast<Protocol::Packet::DataHeader*>(dataPacket.payload)
        ->common.opcode = Protocol::Packet::DATA;
    packets[0] = &dataPacket;
    EXPECT_CALL(*mockReceiver, handleDataPacket(Eq(&dataPacket), _));

    // Set GRANT packet
    Homa::Mock::MockDriver::MockPacket grantPacket{payload[1], 1024};
    static_cast<Protocol::Packet::GrantHeader*>(grantPacket.payload)
        ->common.opcode = Protocol::Packet::GRANT;
    packets[1] = &grantPacket;
    EXPECT_CALL(*mockSender, handleGrantPacket(Eq(&grantPacket)));

    // Set DONE packet
    Homa::Mock::MockDriver::MockPacket donePacket{payload[2], 1024};
    static_cast<Protocol::Packet::DoneHeader*>(donePacket.payload)
        ->common.opcode = Protocol::Packet::DONE;
    packets[2] = &donePacket;
    EXPECT_CALL(*mockSender, handleDonePacket(Eq(&donePacket)));

    // Set RESEND packet
    Homa::Mock::MockDriver::MockPacket resendPacket{payload[3], 1024};
    static_cast<Protocol::Packet::ResendHeader*>(resendPacket.payload)
        ->common.opcode = Protocol::Packet::RESEND;
    packets[3] = &resendPacket;
    EXPECT_CALL(*mockSender, handleResendPacket(Eq(&resendPacket)));

    // Set BUSY packet
    Homa::Mock::MockDriver::MockPacket busyPacket{payload[4], 1024};
    static_cast<Protocol::Packet::PingHeader*>(busyPacket.payload)
        ->common.opcode = Protocol::Packet::BUSY;
    packets[4] = &busyPacket;
    EXPECT_CALL(*mockReceiver, handleBusyPacket(Eq(&busyPacket)));

    // Set PING packet
    Homa::Mock::MockDriver::MockPacket pingPacket{payload[5], 1024};
    static_cast<Protocol::Packet::PingHeader*>(pingPacket.payload)
        ->common.opcode = Protocol::Packet::PING;
    packets[5] = &pingPacket;
    EXPECT_CALL(*mockReceiver, handlePingPacket(Eq(&pingPacket), _));

    // Set UNKNOWN packet
    Homa::Mock::MockDriver::MockPacket unknownPacket{payload[6], 1024};
    static_cast<Protocol::Packet::UnknownHeader*>(unknownPacket.payload)
        ->common.opcode = Protocol::Packet::UNKNOWN;
    packets[6] = &unknownPacket;
    EXPECT_CALL(*mockSender, handleUnknownPacket(Eq(&unknownPacket)));

    // Set ERROR packet
    Homa::Mock::MockDriver::MockPacket errorPacket{payload[7], 1024};
    static_cast<Protocol::Packet::ErrorHeader*>(errorPacket.payload)
        ->common.opcode = Protocol::Packet::ERROR;
    packets[7] = &errorPacket;
    EXPECT_CALL(*mockSender, handleErrorPacket(Eq(&errorPacket)));

    EXPECT_CALL(mockDriver, receivePackets)
        .WillOnce(DoAll(SetArrayArgument<1>(packets, packets + 8), Return(8)));

    transport->processPackets();
}

}  // namespace
}  // namespace Core
}  // namespace Homa
