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

#include <Cycles.h>
#include <Homa/Debug.h>
#include <gtest/gtest.h>

#include "Mock/MockDriver.h"
#include "Mock/MockPolicy.h"
#include "Sender.h"

namespace Homa {
namespace Core {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;

class SenderTest : public ::testing::Test {
  public:
    SenderTest()
        : mockDriver()
        , mockPacket{&payload}
        , mockPolicyManager(&mockDriver)
        , sender()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1031));
        ON_CALL(mockDriver, getQueuedBytes).WillByDefault(Return(0));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        sender = new Sender(22, &mockDriver, &mockPolicyManager,
                            messageTimeoutCycles, pingIntervalCycles);
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~SenderTest()
    {
        delete sender;
        Debug::setLogPolicy(savedLogPolicy);
        PerfUtils::Cycles::mockTscValue = 0;
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    Homa::Mock::MockDriver::MockPacket mockPacket;
    NiceMock<Homa::Mock::MockPolicyManager> mockPolicyManager;
    char payload[1028];
    Sender* sender;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;

    static const uint64_t messageTimeoutCycles = 1000;
    static const uint64_t pingIntervalCycles = 100;

    static Sender::Message* addMessage(Sender* sender, Protocol::MessageId id,
                                       Sender::Message* message,
                                       bool queue = false,
                                       uint16_t packetsGranted = 0)
    {
        message->id = id;
        Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
        bucket->messages.push_back(&message->bucketNode);
        if (queue) {
            Sender::QueuedMessageInfo::ComparePriority comp;
            Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
            info->id = id;
            info->destination = message->destination;
            info->packets = message;
            info->unsentBytes = message->messageLength;
            info->packetsGranted = packetsGranted;
            info->packetsSent = 0;
            // Insert and move message into the correct order in the priority
            // queue.
            sender->sendQueue.push_front(&info->sendQueueNode);
            Intrusive::deprioritize<Sender::Message>(
                &sender->sendQueue, &info->sendQueueNode,
                Sender::QueuedMessageInfo::ComparePriority());
        }
        return message;
    }

    static bool setMessagePacket(Sender::Message* message, int index,
                                 Driver::Packet* packet)
    {
        if (message->occupied.test(index)) {
            return false;
        }
        message->packets[index] = packet;
        message->occupied.set(index);
        message->numPackets++;
        return true;
    }
};

// Used to capture log output.
struct VectorHandler {
    VectorHandler()
        : messages()
    {}
    void operator()(Debug::DebugMessage message)
    {
        messages.push_back(message);
    }
    std::vector<Debug::DebugMessage> messages;
};

TEST_F(SenderTest, allocMessage)
{
    EXPECT_EQ(0U, sender->messageAllocator.pool.outstandingObjects);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
}

TEST_F(SenderTest, handleDonePacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    EXPECT_NE(Homa::OutMessage::Status::COMPLETED, message->state);

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(2);

    // No message.
    sender->handleDonePacket(&mockPacket);

    EXPECT_NE(Homa::OutMessage::Status::COMPLETED, message->state);

    addMessage(sender, id, message);
    message->state = Homa::OutMessage::Status::SENT;

    // Normal expected behavior.
    sender->handleDonePacket(&mockPacket);

    EXPECT_EQ(nullptr, message->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::COMPLETED, message->state);
}

TEST_F(SenderTest, handleDonePacket_CANCELED)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    addMessage(sender, id, message);
    message->state = Homa::OutMessage::Status::CANCELED;

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleDonePacket(&mockPacket);
}

TEST_F(SenderTest, handleDonePacket_COMPLETED)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    addMessage(sender, id, message);
    message->state = Homa::OutMessage::Status::COMPLETED;

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleDonePacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleDonePacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::NOTICE), m.logLevel);
    EXPECT_EQ("Message (42, 1) received duplicate DONE confirmation",
              m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, handleDonePacket_FAILED)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    addMessage(sender, id, message);
    message->state = Homa::OutMessage::Status::FAILED;

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleDonePacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleDonePacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) received DONE confirmation after the message was "
        "already declared FAILED",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, handleDonePacket_IN_PROGRESS)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    addMessage(sender, id, message);
    message->state = Homa::OutMessage::Status::IN_PROGRESS;

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleDonePacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleDonePacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) received DONE confirmation while sending is still "
        "IN_PROGRESS (message not completely sent); DONE is ignored.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, handleDonePacket_NO_STARTED)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    addMessage(sender, id, message);
    message->state = Homa::OutMessage::Status::NOT_STARTED;

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleDonePacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleDonePacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) received DONE confirmation but sending has "
        "NOT_STARTED (message not yet sent); DONE is ignored.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, handleResendPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    std::vector<Homa::Mock::MockDriver::MockPacket*> packets;
    std::vector<int> priorities;
    for (int i = 0; i < 10; ++i) {
        packets.push_back(new Homa::Mock::MockDriver::MockPacket{payload});
        priorities.push_back(0);
        setMessagePacket(message, i, packets[i]);
    }
    SenderTest::addMessage(sender, id, message, true, 5);
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->packetsSent = 5;
    info->priority = 6;
    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(10U, message->numPackets);

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 3;
    resendHdr->num = 5;
    resendHdr->priority = 4;

    EXPECT_CALL(mockPolicyManager, getResendPriority).WillOnce(Return(7));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packets[3]), _, _))
        .WillOnce(
            [&priorities](auto _1, auto _2, int p) { priorities[3] = p; });
    EXPECT_CALL(mockDriver, sendPacket(Eq(packets[4]), _, _))
        .WillOnce(
            [&priorities](auto _1, auto _2, int p) { priorities[4] = p; });
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket);

    EXPECT_EQ(5U, info->packetsSent);
    EXPECT_EQ(8U, info->packetsGranted);
    EXPECT_EQ(4, info->priority);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_EQ(0, priorities[2]);
    EXPECT_EQ(7, priorities[3]);
    EXPECT_EQ(7, priorities[4]);
    EXPECT_EQ(0, priorities[5]);
    EXPECT_TRUE(sender->sendReady.load());

    for (int i = 0; i < 10; ++i) {
        delete packets[i];
    }
}

TEST_F(SenderTest, handleResendPacket_staleResend)
{
    Protocol::MessageId id = {42, 1};
    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 3;
    resendHdr->num = 5;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket);
}

TEST_F(SenderTest, handleResendPacket_badRequest_singlePacketMessage)
{
    Protocol::MessageId id = {42, 1};

    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    Homa::Mock::MockDriver::MockPacket* packet =
        new Homa::Mock::MockDriver::MockPacket{payload};
    setMessagePacket(message, 0, packet);

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 3;
    resendHdr->num = 5;
    resendHdr->priority = 4;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleResendPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleResendPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) with only 1 packet received unexpected RESEND "
        "request; peer Transport may be confused.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    delete packet;
}

TEST_F(SenderTest, handleResendPacket_badRequest_outOfRange)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    std::vector<Homa::Mock::MockDriver::MockPacket*> packets;
    for (int i = 0; i < 10; ++i) {
        packets.push_back(new Homa::Mock::MockDriver::MockPacket{payload});
        setMessagePacket(message, i, packets[i]);
    }
    SenderTest::addMessage(sender, id, message, true, 5);
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->packetsSent = 5;
    info->priority = 6;
    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(10U, message->numPackets);

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 9;
    resendHdr->num = 5;
    resendHdr->priority = 4;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleResendPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleResendPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) RESEND request range out of bounds: requested range "
        "[9, 14); message only contains 10 packets; peer Transport may be "
        "confused.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    for (int i = 0; i < 10; ++i) {
        delete packets[i];
    }
}

TEST_F(SenderTest, handleResendPacket_eagerResend)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    char data[1028];
    Homa::Mock::MockDriver::MockPacket dataPacket{data};
    for (int i = 0; i < 10; ++i) {
        setMessagePacket(message, i, &dataPacket);
    }
    SenderTest::addMessage(sender, id, message, true, 5);
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->packetsSent = 5;
    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(10U, message->numPackets);

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 5;
    resendHdr->num = 3;

    // Expect the BUSY control packet.
    char busy[1028];
    Homa::Mock::MockDriver::MockPacket busyPacket{busy};
    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&busyPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&busyPacket), _, _)).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&busyPacket), Eq(1)))
        .Times(1);

    // Expect no data to be sent but the RESEND packet to be release.
    EXPECT_CALL(mockDriver, sendPacket(Eq(&dataPacket), _, _)).Times(0);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket);

    EXPECT_EQ(5U, info->packetsSent);
    EXPECT_EQ(8U, info->packetsGranted);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::BusyHeader* busyHdr =
        static_cast<Protocol::Packet::BusyHeader*>(mockPacket.payload);
    EXPECT_EQ(id, busyHdr->common.messageId);
}

TEST_F(SenderTest, handleGrantPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message, true, 5);
    message->numPackets = 10;
    message->state = Homa::OutMessage::Status::IN_PROGRESS;
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->priority = 2;
    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->byteLimit = 7000;
    header->priority = 6;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleGrantPacket(&mockPacket);

    EXPECT_EQ(7, info->packetsGranted);
    EXPECT_EQ(6, info->priority);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_TRUE(sender->sendReady.load());
}

TEST_F(SenderTest, handleGrantPacket_excessiveGrant)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message, true, 5);
    message->numPackets = 10;
    message->state = Homa::OutMessage::Status::IN_PROGRESS;
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->priority = 2;
    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->byteLimit = 11000;
    header->priority = 6;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleGrantPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleGrantPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) GRANT exceeds message length; granted packets: 11, "
        "message packets 10; extra grants are ignored.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    EXPECT_EQ(10, info->packetsGranted);
    EXPECT_EQ(6, info->priority);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_TRUE(sender->sendReady.load());
}

TEST_F(SenderTest, handleGrantPacket_staleGrant)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message, true, 5);
    message->numPackets = 10;
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->priority = 2;
    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->byteLimit = 4000;
    header->priority = 6;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleGrantPacket(&mockPacket);

    EXPECT_EQ(5, info->packetsGranted);
    EXPECT_EQ(2, info->priority);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_FALSE(sender->sendReady.load());
}

TEST_F(SenderTest, handleGrantPacket_dropGrant)
{
    Protocol::MessageId id = {42, 1};
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->byteLimit = 4000;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleGrantPacket(&mockPacket);
}

TEST_F(SenderTest, handleUnknownPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    SocketAddress destination = {22, 60001};
    Core::Policy::Unscheduled policyOld = {1, 2000, 1};
    Core::Policy::Unscheduled policyNew = {2, 3000, 2};

    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    std::vector<Homa::Mock::MockDriver::MockPacket*> packets;
    char payload[5][1028];
    for (int i = 0; i < 5; ++i) {
        Homa::Mock::MockDriver::MockPacket* packet =
            new Homa::Mock::MockDriver::MockPacket{payload[i]};
        Protocol::Packet::DataHeader* header =
            static_cast<Protocol::Packet::DataHeader*>(packet->payload);
        header->policyVersion = policyOld.version;
        header->unscheduledIndexLimit = 2;
        packets.push_back(packet);
        setMessagePacket(message, i, packet);
    }
    message->destination = destination;
    message->messageLength = 4500;
    message->state.store(Homa::OutMessage::Status::IN_PROGRESS);
    SenderTest::addMessage(sender, id, message, true, 4);
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    info->id = message->id;
    info->destination = message->destination;
    info->packets = message;
    info->unsentBytes = 0;
    info->packetsGranted = 4;
    info->priority = policyOld.priority;
    info->packetsSent = 4;
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(
        mockPolicyManager,
        getUnscheduledPolicy(Eq(destination.ip), Eq(message->messageLength)))
        .WillOnce(Return(policyNew));
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket);

    EXPECT_EQ(Homa::OutMessage::Status::IN_PROGRESS, message->state);
    for (int i = 0; i < 3; ++i) {
        Homa::Mock::MockDriver::MockPacket* packet = packets[i];
        Protocol::Packet::DataHeader* header =
            static_cast<Protocol::Packet::DataHeader*>(packet->payload);
        EXPECT_EQ(policyNew.version, header->policyVersion);
        EXPECT_EQ(3U, header->unscheduledIndexLimit);
    }
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_EQ(4500U, info->unsentBytes);
    EXPECT_EQ(3U, info->packetsGranted);
    EXPECT_EQ(policyNew.priority, info->priority);
    EXPECT_EQ(0U, info->packetsSent);
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_TRUE(sender->sendReady.load());

    for (int i = 0; i < 5; ++i) {
        delete packets[i];
    }
}

TEST_F(SenderTest, handleUnknownPacket_singlePacketMessage)
{
    Protocol::MessageId id = {42, 1};
    SocketAddress destination = {22, 60001};
    Core::Policy::Unscheduled policyOld = {1, 2000, 1};
    Core::Policy::Unscheduled policyNew = {2, 3000, 2};

    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Homa::Mock::MockDriver::MockPacket dataPacket{payload};
    Protocol::Packet::DataHeader* dataHeader =
        static_cast<Protocol::Packet::DataHeader*>(dataPacket.payload);
    dataHeader->policyVersion = policyOld.version;
    dataHeader->unscheduledIndexLimit = 2;
    setMessagePacket(message, 0, &dataPacket);
    message->destination = destination;
    message->messageLength = 500;
    message->state.store(Homa::OutMessage::Status::SENT);
    SenderTest::addMessage(sender, id, message);
    EXPECT_FALSE(
        sender->sendQueue.contains(&message->queuedMessageInfo.sendQueueNode));
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(
        mockPolicyManager,
        getUnscheduledPolicy(Eq(destination.ip), Eq(message->messageLength)))
        .WillOnce(Return(policyNew));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&dataPacket), _, _)).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket);

    EXPECT_EQ(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_EQ(policyNew.version, dataHeader->policyVersion);
    EXPECT_EQ(3U, dataHeader->unscheduledIndexLimit);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_FALSE(
        sender->sendQueue.contains(&message->queuedMessageInfo.sendQueueNode));
    EXPECT_FALSE(sender->sendReady.load());
}

TEST_F(SenderTest, handleUnknownPacket_NO_KEEP_ALIVE)
{
    Protocol::MessageId id = {42, 1};
    SocketAddress destination = {22, 60001};
    Core::Policy::Unscheduled policyNew = {2, 3000, 2};

    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Homa::Mock::MockDriver::MockPacket dataPacket{payload};
    Protocol::Packet::DataHeader* dataHeader =
        static_cast<Protocol::Packet::DataHeader*>(dataPacket.payload);
    setMessagePacket(message, 0, &dataPacket);
    message->destination = destination;
    message->messageLength = 500;
    message->state.store(Homa::OutMessage::Status::SENT);
    message->options = OutMessage::Options::NO_KEEP_ALIVE;
    SenderTest::addMessage(sender, id, message);
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);
    EXPECT_FALSE(bucket->messageTimeouts.empty());
    EXPECT_FALSE(bucket->pingTimeouts.empty());

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(
        mockPolicyManager,
        getUnscheduledPolicy(Eq(destination.ip), Eq(message->messageLength)))
        .WillOnce(Return(policyNew));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&dataPacket), Eq(destination.ip), _))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket);

    EXPECT_EQ(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_TRUE(bucket->messageTimeouts.empty());
    EXPECT_TRUE(bucket->pingTimeouts.empty());
}

TEST_F(SenderTest, handleUnknownPacket_NO_RETRY)
{
    Protocol::MessageId id = {42, 1};
    SocketAddress destination = {22, 60001};

    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    message->options = OutMessage::Options::NO_RETRY;
    std::vector<Homa::Mock::MockDriver::MockPacket*> packets;
    char payload[5][1028];
    for (int i = 0; i < 5; ++i) {
        Homa::Mock::MockDriver::MockPacket* packet =
            new Homa::Mock::MockDriver::MockPacket{payload[i]};
        packets.push_back(packet);
        setMessagePacket(message, i, packet);
    }
    message->destination = destination;
    message->messageLength = 4500;
    message->state.store(Homa::OutMessage::Status::IN_PROGRESS);
    SenderTest::addMessage(sender, id, message, true);
    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);
    EXPECT_TRUE(
        sender->sendQueue.contains(&message->queuedMessageInfo.sendQueueNode));

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket);

    EXPECT_FALSE(
        sender->sendQueue.contains(&message->queuedMessageInfo.sendQueueNode));
    EXPECT_EQ(nullptr, message->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::FAILED, message->state);
    EXPECT_EQ(Homa::OutMessage::Status::FAILED, message->state);
    EXPECT_FALSE(sender->sendReady.load());
}

TEST_F(SenderTest, handleUnknownPacket_no_message)
{
    Protocol::MessageId id = {42, 1};

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket);
}

TEST_F(SenderTest, handleUnknownPacket_done)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    message->state.store(Homa::OutMessage::Status::COMPLETED);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket);

    EXPECT_EQ(Homa::OutMessage::Status::COMPLETED, message->state);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, handleErrorPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);
    message->state.store(Homa::OutMessage::Status::SENT);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleErrorPacket(&mockPacket);

    EXPECT_EQ(nullptr, message->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::FAILED, message->state);
}

TEST_F(SenderTest, handleErrorPacket_CANCELED)
{
    Protocol::MessageId id = {42, 1};
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    message->state.store(Homa::OutMessage::Status::CANCELED);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleErrorPacket(&mockPacket);

    EXPECT_EQ(Homa::OutMessage::Status::CANCELED, message->state);
}

TEST_F(SenderTest, handleErrorPacket_NOT_STARTED)
{
    Protocol::MessageId id = {42, 1};
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    message->state.store(Homa::OutMessage::Status::NOT_STARTED);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleErrorPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleErrorPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) received ERROR notification but sending has "
        "NOT_STARTED (message not yet sent); ERROR is ignored.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    EXPECT_EQ(Homa::OutMessage::Status::NOT_STARTED, message->state);
}

TEST_F(SenderTest, handleErrorPacket_IN_PROGRESS)
{
    Protocol::MessageId id = {42, 1};
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    message->state.store(Homa::OutMessage::Status::IN_PROGRESS);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleErrorPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleErrorPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) received ERROR notification while sending is still "
        "IN_PROGRESS (message not completely sent); ERROR is ignored.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    EXPECT_EQ(Homa::OutMessage::Status::IN_PROGRESS, message->state);
}

TEST_F(SenderTest, handleErrorPacket_COMPLETED)
{
    Protocol::MessageId id = {42, 1};
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    message->state.store(Homa::OutMessage::Status::COMPLETED);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleErrorPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleErrorPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Message (42, 1) received ERROR notification after the message was "
        "already declared COMPLETED; ERROR is ignored.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    EXPECT_EQ(Homa::OutMessage::Status::COMPLETED, message->state);
}

TEST_F(SenderTest, handleErrorPacket_FAILED)
{
    Protocol::MessageId id = {42, 1};
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message);
    message->state.store(Homa::OutMessage::Status::FAILED);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    sender->handleErrorPacket(&mockPacket);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("handleErrorPacket", m.function);
    EXPECT_EQ(int(Debug::LogLevel::NOTICE), m.logLevel);
    EXPECT_EQ("Message (42, 1) received duplicate ERROR notification.",
              m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());

    EXPECT_EQ(Homa::OutMessage::Status::FAILED, message->state);
}

TEST_F(SenderTest, handleErrorPacket_noMessage)
{
    Protocol::MessageId id = {42, 1};
    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    sender->handleErrorPacket(&mockPacket);
}

TEST_F(SenderTest, poll)
{
    // Nothing to test.
    sender->poll();
}

TEST_F(SenderTest, checkTimeouts)
{
    Sender::MessageBucket* bucket = sender->messageBuckets.buckets.at(0);

    EXPECT_EQ(0, sender->nextBucketIndex.load());

    sender->checkTimeouts();

    EXPECT_EQ(1, sender->nextBucketIndex.load());
}

TEST_F(SenderTest, Message_destructor)
{
    const int MAX_RAW_PACKET_LENGTH = 2000;
    ON_CALL(mockDriver, getMaxPayloadSize)
        .WillByDefault(Return(MAX_RAW_PACKET_LENGTH));
    Sender::Message* msg = new Sender::Message(sender, 0);

    const uint16_t NUM_PKTS = 5;

    msg->numPackets = NUM_PKTS;
    for (int i = 0; i < NUM_PKTS; ++i) {
        msg->occupied.set(i);
    }

    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets), Eq(NUM_PKTS)))
        .Times(1);

    delete msg;
}

TEST_F(SenderTest, Message_append_basic)
{
    const int MAX_RAW_PACKET_LENGTH = 2000;

    ON_CALL(mockDriver, getMaxPayloadSize)
        .WillByDefault(Return(MAX_RAW_PACKET_LENGTH));
    Sender::Message msg(sender, 0);
    char buf[2 * MAX_RAW_PACKET_LENGTH];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + MAX_RAW_PACKET_LENGTH};

    const int TRANSPORT_HEADER_LENGTH = msg.TRANSPORT_HEADER_LENGTH;
    const int PACKET_DATA_LENGTH = msg.PACKET_DATA_LENGTH;

    ASSERT_EQ(MAX_RAW_PACKET_LENGTH,
              TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH);

    char source[] = "Hello, world!";
    setMessagePacket(&msg, 0, &packet0);
    packet0.length = MAX_RAW_PACKET_LENGTH - 7;
    msg.messageLength = PACKET_DATA_LENGTH - 7;

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet1));

    msg.append(source, 14);

    EXPECT_EQ(PACKET_DATA_LENGTH + 7, msg.messageLength);
    EXPECT_EQ(2U, msg.numPackets);
    EXPECT_TRUE(msg.packets[1] == &packet1);
    EXPECT_EQ(MAX_RAW_PACKET_LENGTH, packet0.length);
    EXPECT_EQ(TRANSPORT_HEADER_LENGTH + 7, packet1.length);
    EXPECT_TRUE(std::memcmp(buf + MAX_RAW_PACKET_LENGTH - 7, source, 7) == 0);
    EXPECT_TRUE(
        std::memcmp(buf + MAX_RAW_PACKET_LENGTH + TRANSPORT_HEADER_LENGTH,
                    source + 7, 7) == 0);
}

TEST_F(SenderTest, Message_append_truncated)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    const int MAX_RAW_PACKET_LENGTH = 2000;

    ON_CALL(mockDriver, getMaxPayloadSize)
        .WillByDefault(Return(MAX_RAW_PACKET_LENGTH));
    Sender::Message msg(sender, 0);
    char buf[2 * MAX_RAW_PACKET_LENGTH];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + MAX_RAW_PACKET_LENGTH};

    const int TRANSPORT_HEADER_LENGTH = msg.TRANSPORT_HEADER_LENGTH;
    const int PACKET_DATA_LENGTH = msg.PACKET_DATA_LENGTH;

    char source[] = "Hello, world!";
    setMessagePacket(&msg, msg.MAX_MESSAGE_PACKETS - 1, &packet0);
    packet0.length = msg.TRANSPORT_HEADER_LENGTH + msg.PACKET_DATA_LENGTH - 7;
    msg.messageLength = msg.PACKET_DATA_LENGTH * msg.MAX_MESSAGE_PACKETS - 7;
    EXPECT_EQ(1U, msg.numPackets);

    msg.append(source, 14);

    EXPECT_EQ(msg.PACKET_DATA_LENGTH * msg.MAX_MESSAGE_PACKETS,
              msg.messageLength);
    EXPECT_EQ(1U, msg.numPackets);
    EXPECT_EQ(msg.TRANSPORT_HEADER_LENGTH + msg.PACKET_DATA_LENGTH,
              packet0.length);
    EXPECT_TRUE(std::memcmp(buf + MAX_RAW_PACKET_LENGTH - 7, source, 7) == 0);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("append", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Max message size limit (2016256B) reached; 7 of 14 bytes appended",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, Message_cancel)
{
    // Nothing to test
}

TEST_F(SenderTest, Message_getStatus)
{
    // Nothing to test
}

TEST_F(SenderTest, Message_length)
{
    ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(2048));
    Sender::Message msg(sender, 0);
    msg.messageLength = 200;
    msg.start = 20;
    EXPECT_EQ(180U, msg.length());
}

TEST_F(SenderTest, Message_prepend)
{
    ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(2048));
    Sender::Message msg(sender, 0);
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + 2048};

    const int TRANSPORT_HEADER_LENGTH = msg.TRANSPORT_HEADER_LENGTH;
    const int PACKET_DATA_LENGTH = msg.PACKET_DATA_LENGTH;
    EXPECT_CALL(mockDriver, allocPacket)
        .WillOnce(Return(&packet0))
        .WillOnce(Return(&packet1));
    msg.reserve(PACKET_DATA_LENGTH + 7);
    EXPECT_EQ(PACKET_DATA_LENGTH + 7, msg.start);
    EXPECT_EQ(PACKET_DATA_LENGTH + 7, msg.messageLength);

    char source[] = "Hello, world!";

    msg.prepend(source, 14);

    EXPECT_EQ(PACKET_DATA_LENGTH - 7, msg.start);
    EXPECT_EQ(PACKET_DATA_LENGTH + 7, msg.messageLength);
    EXPECT_TRUE(
        std::memcmp(buf + TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH - 7,
                    source, 7) == 0);
    EXPECT_TRUE(std::memcmp(buf + TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH +
                                TRANSPORT_HEADER_LENGTH,
                            source + 7, 7) == 0);
}

TEST_F(SenderTest, Message_release)
{
    // Nothing to test
}

TEST_F(SenderTest, Message_reserve)
{
    Sender::Message msg(sender, 0);
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + 2048};

    const int TRANSPORT_HEADER_LENGTH = msg.TRANSPORT_HEADER_LENGTH;
    const int PACKET_DATA_LENGTH = msg.PACKET_DATA_LENGTH;

    EXPECT_EQ(0U, msg.start);
    EXPECT_EQ(0U, msg.messageLength);
    EXPECT_EQ(0U, msg.numPackets);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    msg.reserve(PACKET_DATA_LENGTH - 7);

    EXPECT_EQ(PACKET_DATA_LENGTH - 7, msg.start);
    EXPECT_EQ(PACKET_DATA_LENGTH - 7, msg.messageLength);
    EXPECT_EQ(1U, msg.numPackets);
    EXPECT_EQ(&packet0, msg.getPacket(0));
    EXPECT_EQ(TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH - 7, packet0.length);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet1));

    msg.reserve(14);

    EXPECT_EQ(PACKET_DATA_LENGTH + 7, msg.start);
    EXPECT_EQ(PACKET_DATA_LENGTH + 7, msg.messageLength);
    EXPECT_EQ(2U, msg.numPackets);
    EXPECT_EQ(TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH, packet0.length);
    EXPECT_EQ(&packet1, msg.getPacket(1));
    EXPECT_EQ(TRANSPORT_HEADER_LENGTH + 7, packet1.length);
}

TEST_F(SenderTest, Message_send)
{
    // Nothing to test
}

TEST_F(SenderTest, Message_getPacket)
{
    Sender::Message msg(sender, 0);
    Driver::Packet* packet = (Driver::Packet*)42;
    msg.packets[0] = packet;

    EXPECT_EQ(nullptr, msg.getPacket(0));

    msg.occupied.set(0);

    EXPECT_EQ(packet, msg.getPacket(0));
}

TEST_F(SenderTest, Message_getOrAllocPacket)
{
    // TODO(cstlee): cleanup
    Sender::Message msg(sender, 0);
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + 2048};

    EXPECT_FALSE(msg.occupied.test(0));
    EXPECT_EQ(0U, msg.numPackets);
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    EXPECT_TRUE(&packet0 == msg.getOrAllocPacket(0));

    EXPECT_TRUE(msg.occupied.test(0));
    EXPECT_EQ(1U, msg.numPackets);

    EXPECT_TRUE(&packet0 == msg.getOrAllocPacket(0));

    EXPECT_TRUE(msg.occupied.test(0));
    EXPECT_EQ(1U, msg.numPackets);
}

TEST_F(SenderTest, MessageBucket_findMessage)
{
    Sender::MessageBucket* bucket = sender->messageBuckets.buckets.at(0);

    Sender::Message* msg0 =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Sender::Message* msg1 =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    msg0->id = {42, 0};
    msg1->id = {42, 1};
    Protocol::MessageId id_none = {42, 42};

    bucket->messages.push_back(&msg0->bucketNode);
    bucket->messages.push_back(&msg1->bucketNode);

    SpinLock::Lock lock_bucket(bucket->mutex);
    EXPECT_EQ(msg0, bucket->findMessage(msg0->id, lock_bucket));
    EXPECT_EQ(msg1, bucket->findMessage(msg1->id, lock_bucket));
    EXPECT_EQ(nullptr, bucket->findMessage(id_none, lock_bucket));
}

TEST_F(SenderTest, MessageBucketMap_getBucket)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};

    Sender::MessageBucket* bucket0 = sender->messageBuckets.getBucket(id);
    Sender::MessageBucket* bucket1 = sender->messageBuckets.getBucket(id);

    EXPECT_EQ(bucket0, bucket1);
}

TEST_F(SenderTest, sendMessage_basic)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    uint16_t sport = 0;
    uint16_t dport = 60001;
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(sport));
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);

    setMessagePacket(message, 0, &mockPacket);
    message->messageLength = 420;
    mockPacket.length =
        message->messageLength + message->TRANSPORT_HEADER_LENGTH;
    SocketAddress destination = {22, dport};
    Core::Policy::Unscheduled policy = {1, 3000, 2};

    EXPECT_FALSE(bucket->messages.contains(&message->bucketNode));

    EXPECT_CALL(mockPolicyManager,
                getUnscheduledPolicy(Eq(destination.ip), Eq(420)))
        .WillOnce(Return(policy));
    int mockPriority = 0;
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), Eq(destination.ip), _))
        .WillOnce(
            [&mockPriority](auto _1, auto _2, int p) { mockPriority = p; });

    sender->sendMessage(message, destination,
                        Sender::Message::Options::NO_RETRY);

    // Check Message metadata
    EXPECT_EQ(id, message->id);
    EXPECT_EQ(destination.ip, message->destination.ip);
    EXPECT_EQ(destination.port, message->destination.port);
    EXPECT_EQ(Sender::Message::Options::NO_RETRY, message->options);

    // Check packet metadata
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(htobe16(sport), header->common.prefix.sport);
    EXPECT_EQ(htobe16(dport), header->common.prefix.dport);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(420U, header->totalLength);
    EXPECT_EQ(policy.version, header->policyVersion);
    EXPECT_EQ(3U, header->unscheduledIndexLimit);
    EXPECT_EQ(0U, header->index);

    // Check Sender metadata
    EXPECT_TRUE(bucket->messages.contains(&message->bucketNode));
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);

    // Check sent packet metadata
    EXPECT_EQ(policy.priority, mockPriority);

    EXPECT_EQ(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_FALSE(sender->sendReady.load());
}

TEST_F(SenderTest, sendMessage_multipacket)
{
    char payload0[1027];
    char payload1[1027];
    Homa::Mock::MockDriver::MockPacket packet0{payload0};
    Homa::Mock::MockDriver::MockPacket packet1{payload1};
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);

    setMessagePacket(message, 0, &packet0);
    setMessagePacket(message, 1, &packet1);
    message->messageLength = 1420;
    packet0.length = 1000 + 31;
    packet1.length = 420 + 31;
    SocketAddress destination = {22, 60001};
    Core::Policy::Unscheduled policy = {1, 1000, 2};

    EXPECT_EQ(31U, sizeof(Protocol::Packet::DataHeader));
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);
    EXPECT_CALL(mockPolicyManager,
                getUnscheduledPolicy(Eq(destination.ip), Eq(1420)))
        .WillOnce(Return(policy));

    sender->sendMessage(message, destination);

    // Check Message metadata
    EXPECT_EQ(id, message->id);
    EXPECT_EQ(destination.ip, message->destination.ip);
    EXPECT_EQ(destination.port, message->destination.port);
    EXPECT_EQ(Homa::OutMessage::Status::IN_PROGRESS, message->state);

    // Check packet metadata
    Protocol::Packet::DataHeader* header = nullptr;
    // Packet0
    header = static_cast<Protocol::Packet::DataHeader*>(packet0.payload);
    EXPECT_EQ(message->id, header->common.messageId);
    EXPECT_EQ(message->messageLength, header->totalLength);

    // Packet1
    header = static_cast<Protocol::Packet::DataHeader*>(packet1.payload);
    EXPECT_EQ(message->id, header->common.messageId);
    EXPECT_EQ(destination.ip, message->destination.ip);
    EXPECT_EQ(destination.port, message->destination.port);
    EXPECT_EQ(message->messageLength, header->totalLength);

    // Check Sender metadata
    EXPECT_TRUE(bucket->messages.contains(&message->bucketNode));
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);

    // Check sendQueue metadata
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_TRUE(sender->sendReady.load());
}

TEST_F(SenderTest, sendMessage_NO_KEEP_ALIVE)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);

    setMessagePacket(message, 0, &mockPacket);
    message->messageLength = 420;
    mockPacket.length =
        message->messageLength + message->TRANSPORT_HEADER_LENGTH;
    SocketAddress destination = {22, 60001};
    Core::Policy::Unscheduled policy = {1, 3000, 2};

    EXPECT_CALL(mockPolicyManager,
                getUnscheduledPolicy(Eq(destination.ip), Eq(420)))
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), Eq(destination.ip), _))
        .Times(1);

    sender->sendMessage(message, destination,
                        Sender::Message::Options::NO_KEEP_ALIVE);

    EXPECT_EQ(Sender::Message::Options::NO_KEEP_ALIVE, message->options);
    EXPECT_TRUE(bucket->messages.contains(&message->bucketNode));
    EXPECT_TRUE(bucket->messageTimeouts.empty());
    EXPECT_TRUE(bucket->pingTimeouts.empty());
    EXPECT_EQ(Homa::OutMessage::Status::SENT, message->state);
}

TEST_F(SenderTest, sendMessage_missingPacket)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    setMessagePacket(message, 1, &mockPacket);
    Core::Policy::Unscheduled policy = {1, 1000, 2};
    ON_CALL(mockPolicyManager, getUnscheduledPolicy(_, _))
        .WillByDefault(Return(policy));

    EXPECT_DEATH(sender->sendMessage(message, SocketAddress{0, 0}),
                 ".*Incomplete message with id \\(22:1\\); missing packet at "
                 "offset 0; this shouldn't happen.*");
}

TEST_F(SenderTest, sendMessage_unscheduledLimit)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    for (int i = 0; i < 9; ++i) {
        setMessagePacket(message, i, &mockPacket);
    }
    message->messageLength = 9000;
    mockPacket.length = 1000 + sizeof(Protocol::Packet::DataHeader);
    SocketAddress destination = {22, 60001};
    Core::Policy::Unscheduled policy = {1, 4500, 2};
    EXPECT_EQ(9U, message->numPackets);
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);
    EXPECT_CALL(mockPolicyManager, getUnscheduledPolicy(destination.ip, 9000))
        .WillOnce(Return(policy));

    sender->sendMessage(message, destination);

    // Check sendQueue metadata
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    EXPECT_EQ(5U, info->packetsGranted);
}

TEST_F(SenderTest, cancelMessage)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    SenderTest::addMessage(sender, id, message, true, 5);
    Sender::MessageBucket* bucket = sender->messageBuckets.getBucket(id);
    bucket->pingTimeouts.setTimeout(&message->pingTimeout);
    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    message->messageLength = 9000;
    message->numPackets = 9;
    message->state = Homa::OutMessage::Status::IN_PROGRESS;
    EXPECT_FALSE(bucket->messageTimeouts.list.empty());
    EXPECT_FALSE(bucket->pingTimeouts.list.empty());
    EXPECT_FALSE(sender->sendQueue.empty());

    sender->cancelMessage(message);

    EXPECT_TRUE(bucket->messageTimeouts.list.empty());
    EXPECT_TRUE(bucket->pingTimeouts.list.empty());
    EXPECT_TRUE(sender->sendQueue.empty());
    EXPECT_EQ(Homa::OutMessage::Status::CANCELED, message->state.load());
}

TEST_F(SenderTest, dropMessage_basic)
{
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
    EXPECT_TRUE(message->held);
    EXPECT_EQ(OutMessage::Status::NOT_STARTED, message->state);

    sender->dropMessage(message);

    EXPECT_EQ(0U, sender->messageAllocator.pool.outstandingObjects);
}

TEST_F(SenderTest, dropMessage_IN_PROGRESS)
{
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    message->state = OutMessage::Status::IN_PROGRESS;
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
    EXPECT_TRUE(message->held);

    sender->dropMessage(message);

    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
    EXPECT_FALSE(message->held);
}

TEST_F(SenderTest, checkMessageTimeouts)
{
    Sender::Message* message[4];
    Sender::MessageBucket* bucket = sender->messageBuckets.buckets.at(0);
    for (uint64_t i = 0; i < 4; ++i) {
        message[i] = dynamic_cast<Sender::Message*>(sender->allocMessage(0));
        bucket->messageTimeouts.setTimeout(&message[i]->messageTimeout);
        bucket->pingTimeouts.setTimeout(&message[i]->pingTimeout);
    }

    // Message[0]: Normal timeout: IN_PROGRESS
    message[0]->messageTimeout.expirationCycleTime = 9998;
    message[0]->state = Homa::OutMessage::Status::IN_PROGRESS;
    sender->sendQueue.push_front(&message[0]->queuedMessageInfo.sendQueueNode);
    // Message[1]: Normal timeout: SENT
    message[1]->messageTimeout.expirationCycleTime = 9999;
    message[1]->state = Homa::OutMessage::Status::SENT;
    // Message[2]: Normal timeout: COMPLETED
    message[2]->messageTimeout.expirationCycleTime = 10000;
    message[2]->state = Homa::OutMessage::Status::COMPLETED;
    // Message[3]: No timeout
    message[3]->messageTimeout.expirationCycleTime = 10001;
    message[3]->state = Homa::OutMessage::Status::SENT;

    bucket->messageTimeouts.nextTimeout = 9998;

    sender->checkMessageTimeouts(10000, bucket);

    EXPECT_EQ(message[3]->messageTimeout.expirationCycleTime,
              bucket->messageTimeouts.nextTimeout.load());
    // Message[0]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(nullptr, message[0]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::FAILED, message[0]->getStatus());
    EXPECT_TRUE(sender->sendQueue.empty());
    // Message[1]: Normal timeout: SENT
    EXPECT_EQ(nullptr, message[1]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[1]->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::FAILED, message[1]->getStatus());
    // Message[2]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[2]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[2]->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::COMPLETED, message[2]->getStatus());
    // Message[3]: No timeout
    EXPECT_EQ(&bucket->messageTimeouts.list,
              message[3]->messageTimeout.node.list);
    EXPECT_EQ(&bucket->pingTimeouts.list, message[3]->pingTimeout.node.list);
    EXPECT_EQ(Homa::OutMessage::Status::SENT, message[3]->getStatus());
}

TEST_F(SenderTest, checkPingTimeouts)
{
    Sender::Message* message[6];
    Sender::MessageBucket* bucket = sender->messageBuckets.buckets.at(0);
    for (uint64_t i = 0; i < 6; ++i) {
        message[i] = dynamic_cast<Sender::Message*>(sender->allocMessage(0));
        bucket->pingTimeouts.setTimeout(&message[i]->pingTimeout);
    }

    // Message[0]: Normal timeout: COMPLETED
    message[0]->state = Homa::OutMessage::Status::COMPLETED;
    message[0]->pingTimeout.expirationCycleTime = 9996;
    // Message[1]: Normal timeout: FAILED
    message[1]->state = Homa::OutMessage::Status::FAILED;
    message[1]->pingTimeout.expirationCycleTime = 9997;
    // Message[2]: Normal timeout: NO_KEEP_ALIVE && SENT
    message[2]->options = Homa::OutMessage::Options::NO_KEEP_ALIVE;
    message[2]->state = Homa::OutMessage::Status::SENT;
    message[2]->pingTimeout.expirationCycleTime = 9998;
    // Message[3]: Normal timeout: IN_PROGRESS
    message[3]->state = Homa::OutMessage::Status::IN_PROGRESS;
    message[3]->pingTimeout.expirationCycleTime = 9999;
    message[3]->queuedMessageInfo.packetsSent = 1;
    message[3]->queuedMessageInfo.packetsGranted = 2;
    // Message[4]: Normal timeout: SENT
    message[4]->state = Homa::OutMessage::Status::SENT;
    message[4]->pingTimeout.expirationCycleTime = 10000;
    // Message[5]: No timeout
    message[5]->pingTimeout.expirationCycleTime = 10001;

    bucket->pingTimeouts.nextTimeout = 9996;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), _, _)).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->checkPingTimeouts(10000, bucket);

    EXPECT_EQ(message[5]->pingTimeout.expirationCycleTime,
              bucket->pingTimeouts.nextTimeout.load());
    // Message[0]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[0]->pingTimeout.node.list);
    // Message[1]: Normal timeout: FAILED
    EXPECT_EQ(nullptr, message[1]->pingTimeout.node.list);
    // Message[2]: Normal timeout: NO_KEEP_ALIVE && SENT
    EXPECT_EQ(nullptr, message[2]->pingTimeout.node.list);
    // Message[3]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(10100, message[4]->pingTimeout.expirationCycleTime);
    // Message[4]: Normal timeout: SENT
    EXPECT_EQ(10100, message[4]->pingTimeout.expirationCycleTime);
    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::PING, header->opcode);
    EXPECT_EQ(message[4]->id, header->messageId);
    // Message[5]: No timeout
    EXPECT_EQ(10001, message[5]->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, trySend_basic)
{
    Protocol::MessageId id = {42, 10};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    SenderTest::addMessage(sender, id, message, true, 3);
    Homa::Mock::MockDriver::MockPacket* packet[5];
    const uint32_t PACKET_SIZE = sender->driver->getMaxPayloadSize();
    const uint32_t PACKET_DATA_SIZE =
        PACKET_SIZE - message->TRANSPORT_HEADER_LENGTH;
    for (int i = 0; i < 5; ++i) {
        packet[i] = new Homa::Mock::MockDriver::MockPacket{payload};
        packet[i]->length = PACKET_SIZE;
        setMessagePacket(message, i, packet[i]);
        info->unsentBytes += PACKET_DATA_SIZE;
    }
    message->state = Homa::OutMessage::Status::IN_PROGRESS;
    message->held = false;
    sender->sendReady = true;
    EXPECT_EQ(5U, message->numPackets);
    EXPECT_EQ(3U, info->packetsGranted);
    EXPECT_EQ(0U, info->packetsSent);
    EXPECT_EQ(5 * PACKET_DATA_SIZE, info->unsentBytes);
    EXPECT_NE(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);

    // 3 granted packets; 2 will send; queue limit reached.
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[0]), _, _));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[1]), _, _));
    sender->trySend();  // < test call
    EXPECT_TRUE(sender->sendReady);
    EXPECT_EQ(Homa::OutMessage::Status::IN_PROGRESS, message->state);
    EXPECT_EQ(3U, info->packetsGranted);
    EXPECT_EQ(2U, info->packetsSent);
    EXPECT_EQ(3 * PACKET_DATA_SIZE, info->unsentBytes);
    EXPECT_NE(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // 1 packet to be sent; grant limit reached.
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[2]), _, _));
    sender->trySend();  // < test call
    EXPECT_FALSE(sender->sendReady);
    EXPECT_EQ(Homa::OutMessage::Status::IN_PROGRESS, message->state);
    EXPECT_EQ(3U, info->packetsGranted);
    EXPECT_EQ(3U, info->packetsSent);
    EXPECT_EQ(2 * PACKET_DATA_SIZE, info->unsentBytes);
    EXPECT_NE(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // No additional grants; spurious ready hint.
    EXPECT_CALL(mockDriver, sendPacket).Times(0);
    sender->sendReady = true;
    sender->trySend();  // < test call
    EXPECT_FALSE(sender->sendReady);
    EXPECT_EQ(Homa::OutMessage::Status::IN_PROGRESS, message->state);
    EXPECT_EQ(3U, info->packetsGranted);
    EXPECT_EQ(3U, info->packetsSent);
    EXPECT_EQ(2 * PACKET_DATA_SIZE, info->unsentBytes);
    EXPECT_NE(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_TRUE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_EQ(1U, sender->messageAllocator.pool.outstandingObjects);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // 2 more granted packets; will finish.
    info->packetsGranted = 5;
    sender->sendReady = true;
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[3]), _, _));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[4]), _, _));
    sender->trySend();  // < test call
    EXPECT_FALSE(sender->sendReady);
    EXPECT_EQ(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_EQ(5U, info->packetsGranted);
    EXPECT_EQ(5U, info->packetsSent);
    EXPECT_EQ(0 * PACKET_DATA_SIZE, info->unsentBytes);
    EXPECT_EQ(Homa::OutMessage::Status::SENT, message->state);
    EXPECT_FALSE(sender->sendQueue.contains(&info->sendQueueNode));
    EXPECT_EQ(0U, sender->messageAllocator.pool.outstandingObjects);
    Mock::VerifyAndClearExpectations(&mockDriver);

    for (int i = 0; i < 5; ++i) {
        delete packet[i];
    }
}

TEST_F(SenderTest, trySend_multipleMessages)
{
    Protocol::MessageId id[3];
    Sender::Message* message[3];
    Sender::QueuedMessageInfo* info[3];
    Sender::MessageBucket* bucket[3];
    Homa::Mock::MockDriver::MockPacket* packet[3];
    for (uint64_t i = 0; i < 3; ++i) {
        id[i] = {22, 10 + i};
        message[i] = dynamic_cast<Sender::Message*>(sender->allocMessage(0));
        info[i] = &message[i]->queuedMessageInfo;
        SenderTest::addMessage(sender, id[i], message[i], true, 1);
        bucket[i] = sender->messageBuckets.getBucket(id[i]);
        packet[i] = new Homa::Mock::MockDriver::MockPacket{payload};
        packet[i]->length = sender->driver->getMaxPayloadSize() / 4;
        setMessagePacket(message[i], 0, packet[i]);
        info[i]->unsentBytes +=
            (packet[i]->length - message[i]->TRANSPORT_HEADER_LENGTH);
        message[i]->state = Homa::OutMessage::Status::IN_PROGRESS;
    }
    sender->sendReady = true;

    // Message 0: Will finish, !held
    EXPECT_EQ(1, info[0]->packetsGranted);
    info[0]->packetsSent = 0;
    message[0]->held = false;

    // Message 1: Will reach grant limit
    EXPECT_EQ(1, info[1]->packetsGranted);
    info[1]->packetsSent = 0;
    setMessagePacket(message[1], 1, nullptr);
    EXPECT_EQ(2, message[1]->numPackets);

    // Message 2: Will finish, NO_KEEP_ALIVE
    EXPECT_EQ(1, info[2]->packetsGranted);
    info[2]->packetsSent = 0;
    message[2]->options = OutMessage::Options::NO_KEEP_ALIVE;

    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[0]), _, _));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[1]), _, _));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[2]), _, _));

    sender->trySend();

    EXPECT_EQ(1U, info[0]->packetsSent);
    EXPECT_EQ(Homa::OutMessage::Status::SENT, message[0]->state);
    EXPECT_FALSE(sender->sendQueue.contains(&info[0]->sendQueueNode));
    EXPECT_EQ(nullptr,
              bucket[0]->findMessage(id[0], SpinLock::Lock(bucket[0]->mutex)));
    EXPECT_EQ(1U, info[1]->packetsSent);
    EXPECT_NE(Homa::OutMessage::Status::SENT, message[1]->state);
    EXPECT_TRUE(sender->sendQueue.contains(&info[1]->sendQueueNode));
    EXPECT_EQ(1U, info[2]->packetsSent);
    EXPECT_EQ(Homa::OutMessage::Status::SENT, message[2]->state);
    EXPECT_FALSE(sender->sendQueue.contains(&info[2]->sendQueueNode));
    EXPECT_FALSE(bucket[2]->messageTimeouts.list.contains(
        &message[2]->messageTimeout.node));
    EXPECT_FALSE(
        bucket[2]->pingTimeouts.list.contains(&message[2]->pingTimeout.node));
}

TEST_F(SenderTest, trySend_alreadyRunning)
{
    Protocol::MessageId id = {42, 1};
    Sender::Message* message =
        dynamic_cast<Sender::Message*>(sender->allocMessage(0));
    Sender::QueuedMessageInfo* info = &message->queuedMessageInfo;
    SenderTest::addMessage(sender, id, message, true, 1);
    setMessagePacket(message, 0, &mockPacket);
    message->messageLength = 1000;
    EXPECT_EQ(1U, message->numPackets);
    EXPECT_EQ(1, info->packetsGranted);
    EXPECT_EQ(0, info->packetsSent);

    sender->sending.test_and_set();

    EXPECT_CALL(mockDriver, sendPacket).Times(0);

    sender->trySend();

    EXPECT_EQ(0, info->packetsSent);
}

TEST_F(SenderTest, trySend_nothingToSend)
{
    EXPECT_TRUE(sender->sendQueue.empty());
    EXPECT_CALL(mockDriver, sendPacket).Times(0);
    sender->trySend();
}

}  // namespace
}  // namespace Core
}  // namespace Homa
