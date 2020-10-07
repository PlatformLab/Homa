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

#include <mutex>

#include "Mock/MockDriver.h"
#include "Mock/MockPolicy.h"
#include "Receiver.h"
#include "TransportImpl.h"

namespace Homa {
namespace Core {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Matcher;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;

/// Helper macro to construct an IpAddress from a numeric number.
#define IP(x) \
    IpAddress \
    {         \
        x     \
    }

class ReceiverTest : public ::testing::Test {
  public:
    ReceiverTest()
        : mockDriver()
        , mockPacket{&payload}
        , mockPolicyManager(&mockDriver)
        , payload()
        , receiver()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1027));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        receiver = new Receiver(&mockDriver, &mockPolicyManager,
                                messageTimeoutCycles, resendIntervalCycles);
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~ReceiverTest()
    {
        Mock::VerifyAndClearExpectations(&mockDriver);
        delete receiver;
        Debug::setLogPolicy(savedLogPolicy);
        PerfUtils::Cycles::mockTscValue = 0;
    }

    static const uint64_t messageTimeoutCycles = 1000;
    static const uint64_t resendIntervalCycles = 100;

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    Homa::Mock::MockDriver::MockPacket mockPacket;
    NiceMock<Homa::Mock::MockPolicyManager> mockPolicyManager;
    char payload[1028];
    Receiver* receiver;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
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

TEST_F(ReceiverTest, handleDataPacket)
{
    const Protocol::MessageId id(42, 33);
    const uint32_t totalMessageLength = 3500;
    const uint8_t policyVersion = 1;
    const uint16_t HEADER_SIZE = sizeof(Protocol::Packet::DataHeader);

    Receiver::Message* message = nullptr;
    Receiver::ScheduledMessageInfo* info = nullptr;
    Receiver::MessageBucket* bucket = receiver->messageBuckets.getBucket(id);

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.opcode = Protocol::Packet::DATA;
    header->common.messageId = id;
    header->totalLength = totalMessageLength;
    header->policyVersion = policyVersion;
    header->unscheduledIndexLimit = 1;
    IpAddress sourceIp{22};

    // -------------------------------------------------------------------------
    // Receive packet[1]. New message.
    header->index = 1;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockPolicyManager,
                signalNewMessage(Eq(sourceIp), Eq(policyVersion),
                                 Eq(totalMessageLength)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, sourceIp);
    // ---------

    {
        SpinLock::Lock lock_bucket(bucket->mutex);
        message = bucket->findMessage(id, lock_bucket);
    }
    ASSERT_NE(nullptr, message);
    EXPECT_EQ(id, message->id);
    EXPECT_EQ(totalMessageLength, message->messageLength);
    EXPECT_EQ(4U, message->numExpectedPackets);
    EXPECT_EQ(Receiver::Message::State::IN_PROGRESS, message->state);
    ASSERT_TRUE(message->scheduled);
    info = &message->scheduledMessageInfo;
    EXPECT_NE(nullptr, info->peer);
    EXPECT_EQ(totalMessageLength, info->messageLength);
    EXPECT_EQ(totalMessageLength - 1000, info->bytesRemaining);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
    EXPECT_EQ(1U, message->numPackets);
    EXPECT_EQ(2500U, info->bytesRemaining);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[1]. Duplicate.
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, sourceIp);
    // ---------

    EXPECT_EQ(1U, message->numPackets);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[2].
    header->index = 2;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, sourceIp);
    // ---------

    EXPECT_EQ(2U, message->numPackets);
    EXPECT_EQ(1500U, info->bytesRemaining);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[3].
    header->index = 3;
    mockPacket.length = HEADER_SIZE + 500;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, sourceIp);
    // ---------

    EXPECT_EQ(3U, message->numPackets);
    EXPECT_EQ(1000U, info->bytesRemaining);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[0]. Finished.
    header->index = 0;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, sourceIp);
    // ---------

    EXPECT_EQ(4U, message->numPackets);
    EXPECT_EQ(0U, info->bytesRemaining);
    EXPECT_EQ(Receiver::Message::State::COMPLETED, message->state);
    EXPECT_EQ(message, &receiver->receivedMessages.queue.back());
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[0]. Already finished.
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, sourceIp);
    // ---------

    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, handleBusyPacket_basic)
{
    Protocol::MessageId id(42, 32);
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{0, 60001}, 0);
    Receiver::MessageBucket* bucket = receiver->messageBuckets.getBucket(id);
    bucket->messages.push_back(&message->bucketNode);

    Protocol::Packet::BusyHeader* busyHeader =
        (Protocol::Packet::BusyHeader*)mockPacket.payload;
    busyHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->handleBusyPacket(&mockPacket);

    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
}

TEST_F(ReceiverTest, handleBusyPacket_unknown)
{
    Protocol::MessageId id(42, 32);

    Protocol::Packet::BusyHeader* busyHeader =
        (Protocol::Packet::BusyHeader*)mockPacket.payload;
    busyHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->handleBusyPacket(&mockPacket);
}

TEST_F(ReceiverTest, handlePingPacket_basic)
{
    Protocol::MessageId id(42, 32);
    IpAddress mockAddress{22};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 20000, id, SocketAddress{mockAddress, 0}, 0);
    ASSERT_TRUE(message->scheduled);
    Receiver::ScheduledMessageInfo* info = &message->scheduledMessageInfo;
    info->bytesGranted = 500;
    info->priority = 3;

    Receiver::MessageBucket* bucket = receiver->messageBuckets.getBucket(id);
    bucket->messages.push_back(&message->bucketNode);

    char pingPayload[1028];
    Homa::Mock::MockDriver::MockPacket pingPacket{pingPayload};
    IpAddress sourceIp = mockAddress;
    Protocol::Packet::PingHeader* pingHeader =
        (Protocol::Packet::PingHeader*)pingPacket.payload;
    pingHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), Eq(mockAddress), _))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&pingPacket), Eq(1)))
        .Times(1);

    receiver->handlePingPacket(&pingPacket, sourceIp);

    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->resendTimeout.expirationCycleTime);

    Protocol::Packet::GrantHeader* header =
        (Protocol::Packet::GrantHeader*)payload;
    EXPECT_EQ(Protocol::Packet::GRANT, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(500, header->byteLimit);
    EXPECT_EQ(3, header->priority);
}

TEST_F(ReceiverTest, handlePingPacket_unknown)
{
    Protocol::MessageId id(42, 32);

    char pingPayload[1028];
    Homa::Mock::MockDriver::MockPacket pingPacket{pingPayload};
    IpAddress mockAddress{22};
    Protocol::Packet::PingHeader* pingHeader =
        (Protocol::Packet::PingHeader*)pingPacket.payload;
    pingHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), Eq(mockAddress), _))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&pingPacket), Eq(1)))
        .Times(1);

    receiver->handlePingPacket(&pingPacket, mockAddress);

    Protocol::Packet::UnknownHeader* header =
        (Protocol::Packet::UnknownHeader*)payload;
    EXPECT_EQ(Protocol::Packet::UNKNOWN, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
}

TEST_F(ReceiverTest, receiveMessage)
{
    Receiver::Message* msg0 = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, Protocol::MessageId(42, 0),
        SocketAddress{22, 60001}, 0);
    Receiver::Message* msg1 = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, Protocol::MessageId(42, 0),
        SocketAddress{22, 60001}, 0);

    receiver->receivedMessages.queue.push_back(&msg0->receivedMessageNode);
    receiver->receivedMessages.queue.push_back(&msg1->receivedMessageNode);
    EXPECT_FALSE(receiver->receivedMessages.queue.empty());

    EXPECT_EQ(msg0, receiver->receiveMessage());
    EXPECT_FALSE(receiver->receivedMessages.queue.empty());

    EXPECT_EQ(msg1, receiver->receiveMessage());
    EXPECT_TRUE(receiver->receivedMessages.queue.empty());

    EXPECT_EQ(nullptr, receiver->receiveMessage());
    EXPECT_TRUE(receiver->receivedMessages.queue.empty());
}

TEST_F(ReceiverTest, poll)
{
    // Nothing to test
    receiver->poll();
}

TEST_F(ReceiverTest, checkTimeouts)
{
    Receiver::MessageBucket* bucket = receiver->messageBuckets.buckets.at(0);

    EXPECT_EQ(0, receiver->nextBucketIndex.load());

    receiver->checkTimeouts();

    EXPECT_EQ(1, receiver->nextBucketIndex.load());
}

TEST_F(ReceiverTest, Message_destructor_basic)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);

    const uint16_t NUM_PKTS = 5;

    message->numPackets = NUM_PKTS;
    for (int i = 0; i < NUM_PKTS; ++i) {
        message->occupied.set(i);
    }

    EXPECT_CALL(mockDriver, releasePackets(Eq(message->packets), Eq(NUM_PKTS)))
        .Times(1);

    receiver->messageAllocator.pool.destroy(message);
}

TEST_F(ReceiverTest, Message_destructor_holes)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);

    const uint16_t NUM_PKTS = 4;

    message->numPackets = NUM_PKTS;
    message->occupied.set(0);
    message->occupied.set(1);
    message->occupied.set(3);
    message->occupied.set(4);

    EXPECT_CALL(mockDriver, releasePackets(Eq(&message->packets[0]), Eq(2)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(&message->packets[3]), Eq(2)))
        .Times(1);

    receiver->messageAllocator.pool.destroy(message);
}

TEST_F(ReceiverTest, Message_acknowledge)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver,
                sendPacket(Eq(&mockPacket), Eq(message->source.ip), _))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    message->acknowledge();

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::DONE, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::DoneHeader), mockPacket.length);
}

TEST_F(ReceiverTest, Message_dropped)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);

    message->state = Receiver::Message::State::IN_PROGRESS;

    EXPECT_FALSE(message->dropped());

    message->state = Receiver::Message::State::DROPPED;

    EXPECT_TRUE(message->dropped());
}

TEST_F(ReceiverTest, Message_fail)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver,
                sendPacket(Eq(&mockPacket), Eq(message->source.ip), _))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    message->fail();

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::ERROR, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::ErrorHeader), mockPacket.length);
}

TEST_F(ReceiverTest, Message_get_basic)
{
    ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(2048));
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 24, 24 + 2007, id, SocketAddress{22, 60001}, 0);
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + 2048};

    char source[] = "Hello, world!";
    message->setPacket(0, &packet0);
    message->setPacket(1, &packet1);
    std::memcpy(buf + 24 + 24 + 2000 - 7, source, 7);
    std::memcpy(buf + 24 + 24 + 2000 + 24, source + 7, 7);
    packet0.length = 24 + 24 + 2000;
    packet1.length = 24 + 7;
    message->start = 24;
    EXPECT_EQ(24U, message->TRANSPORT_HEADER_LENGTH);

    char dest[4096];
    size_t bytes = message->get(2000 - 7, dest, 20);

    EXPECT_EQ(14U, bytes);
    EXPECT_STREQ(source, dest);
}

TEST_F(ReceiverTest, Message_get_offsetTooLarge)
{
    ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(2048));
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 24, 24 + 2007, id, SocketAddress{22, 60001}, 0);
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + 2048};

    message->setPacket(0, &packet0);
    message->setPacket(1, &packet1);
    packet0.length = 24 + 24 + 2000;
    packet1.length = 24 + 7;
    message->start = 20;
    EXPECT_EQ(24U, message->TRANSPORT_HEADER_LENGTH);

    char dest[4096];
    uint32_t bytes = message->get(4000, dest, 20);

    EXPECT_EQ(0U, bytes);
}

TEST_F(ReceiverTest, Message_get_missingPacket)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(2048));
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 24, 24 + 2007, id, SocketAddress{22, 60001}, 0);
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0{buf + 0};
    Homa::Mock::MockDriver::MockPacket packet1{buf + 2048};

    char source[] = "Hello,";
    message->setPacket(0, &packet0);
    std::memcpy(buf + 24 + 24 + 2000 - 7, source, 7);
    packet0.length = 24 + 24 + 2000;
    message->start = 24;
    EXPECT_EQ(24U, message->TRANSPORT_HEADER_LENGTH);

    char dest[4096];
    uint32_t bytes = message->get(2000 - 7, dest, 20);

    EXPECT_EQ(7U, bytes);
    EXPECT_STREQ(source, dest);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Receiver.cc", m.filename);
    EXPECT_STREQ("get", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ("Message is missing data starting at packet index 1", m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(ReceiverTest, Message_length)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);
    message->messageLength = 200;
    message->start = 20;
    EXPECT_EQ(180U, message->length());
}

TEST_F(ReceiverTest, Message_strip)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);
    message->messageLength = 30;
    message->start = 0;

    message->strip(20);

    EXPECT_EQ(20U, message->start);

    message->strip(20);

    EXPECT_EQ(30U, message->start);
}

TEST_F(ReceiverTest, Message_release)
{
    // Nothing to test
}

TEST_F(ReceiverTest, Message_getPacket)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);

    Driver::Packet* packet = (Driver::Packet*)42;
    message->packets[0] = packet;

    EXPECT_EQ(nullptr, message->getPacket(0));

    message->occupied.set(0);

    EXPECT_EQ(packet, message->getPacket(0));
}

TEST_F(ReceiverTest, Message_setPacket)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 0, id, SocketAddress{22, 60001}, 0);
    Driver::Packet* packet = (Driver::Packet*)42;

    EXPECT_FALSE(message->occupied.test(0));
    EXPECT_EQ(0U, message->numPackets);

    EXPECT_TRUE(message->setPacket(0, packet));

    EXPECT_EQ(packet, message->packets[0]);
    EXPECT_TRUE(message->occupied.test(0));
    EXPECT_EQ(1U, message->numPackets);

    EXPECT_FALSE(message->setPacket(0, packet));
}

TEST_F(ReceiverTest, MessageBucket_findMessage)
{
    Receiver::MessageBucket* bucket = receiver->messageBuckets.buckets.at(0);

    Protocol::MessageId id0 = {42, 0};
    Receiver::Message* msg0 = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 0, id0,
        SocketAddress{0, 60001}, 0);
    Protocol::MessageId id1 = {42, 1};
    Receiver::Message* msg1 = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 0, id1,
        SocketAddress{0, 60001}, 0);
    Protocol::MessageId id_none = {42, 42};

    bucket->messages.push_back(&msg0->bucketNode);
    bucket->messages.push_back(&msg1->bucketNode);

    SpinLock::Lock lock_bucket(bucket->mutex);
    EXPECT_EQ(msg0, bucket->findMessage(msg0->id, lock_bucket));
    EXPECT_EQ(msg1, bucket->findMessage(msg1->id, lock_bucket));
    EXPECT_EQ(nullptr, bucket->findMessage(id_none, lock_bucket));
}

TEST_F(ReceiverTest, MessageBucketMap_getBucket)
{
    Protocol::MessageId id = {42, 22};

    Receiver::MessageBucket* bucket0 = receiver->messageBuckets.getBucket(id);
    Receiver::MessageBucket* bucket1 = receiver->messageBuckets.getBucket(id);

    EXPECT_EQ(bucket0, bucket1);
}

TEST_F(ReceiverTest, dropMessage)
{
    SpinLock dummyMutex;
    SpinLock::Lock dummy(dummyMutex);
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, 0, 1000, id, SocketAddress{22, 60001}, 0);
    ASSERT_TRUE(message->scheduled);
    Receiver::MessageBucket* bucket = receiver->messageBuckets.getBucket(id);

    bucket->messages.push_back(&message->bucketNode);
    receiver->schedule(message, dummy);
    bucket->messageTimeouts.setTimeout(&message->messageTimeout);
    bucket->resendTimeouts.setTimeout(&message->resendTimeout);

    EXPECT_EQ(1U, receiver->messageAllocator.pool.outstandingObjects);
    EXPECT_EQ(message, bucket->findMessage(id, dummy));
    EXPECT_EQ(&receiver->peerTable[message->source.ip],
              message->scheduledMessageInfo.peer);
    EXPECT_FALSE(bucket->messageTimeouts.list.empty());
    EXPECT_FALSE(bucket->resendTimeouts.list.empty());

    receiver->dropMessage(message);

    EXPECT_EQ(0U, receiver->messageAllocator.pool.outstandingObjects);
    EXPECT_EQ(nullptr, bucket->findMessage(id, dummy));
    EXPECT_EQ(nullptr, message->scheduledMessageInfo.peer);
    EXPECT_TRUE(bucket->messageTimeouts.list.empty());
    EXPECT_TRUE(bucket->resendTimeouts.list.empty());
}

TEST_F(ReceiverTest, checkMessageTimeouts)
{
    void* op[3];
    Receiver::Message* message[3];
    Receiver::MessageBucket* bucket = receiver->messageBuckets.buckets.at(0);
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        op[i] = reinterpret_cast<void*>(i);
        message[i] = receiver->messageAllocator.pool.construct(
            receiver, &mockDriver, 0, 1000, id, SocketAddress{0, 60001}, 0);
        bucket->messages.push_back(&message[i]->bucketNode);
        bucket->messageTimeouts.setTimeout(&message[i]->messageTimeout);
        bucket->resendTimeouts.setTimeout(&message[i]->resendTimeout);
    }
    ASSERT_EQ(3U, receiver->messageAllocator.pool.outstandingObjects);

    // Message[0]: Normal timeout: IN_PROGRESS
    message[0]->messageTimeout.expirationCycleTime = 9998;
    ASSERT_EQ(Receiver::Message::State::IN_PROGRESS, message[0]->state.load());
    ASSERT_TRUE(message[0]->scheduled);
    {
        SpinLock::Lock lock_scheduler(receiver->schedulerMutex);
        receiver->schedule(message[0], lock_scheduler);
    }

    // Message[1]: Normal timeout: COMPLETED
    message[1]->messageTimeout.expirationCycleTime = 10000;
    message[1]->state = Receiver::Message::State::COMPLETED;

    // Message[2]: No timeout
    message[2]->messageTimeout.expirationCycleTime = 10001;

    bucket->messageTimeouts.nextTimeout = 9998;

    ASSERT_EQ(10000U, PerfUtils::Cycles::rdtsc());
    ASSERT_TRUE(message[0]->messageTimeout.hasElapsed());
    ASSERT_TRUE(message[1]->messageTimeout.hasElapsed());
    ASSERT_FALSE(message[2]->messageTimeout.hasElapsed());

    receiver->checkMessageTimeouts(10000, bucket);

    EXPECT_EQ(message[2]->messageTimeout.expirationCycleTime,
              bucket->messageTimeouts.nextTimeout.load());

    // Message[0]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(nullptr, message[0]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->resendTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->scheduledMessageInfo.peer);
    EXPECT_FALSE(bucket->messages.contains(&message[0]->bucketNode));
    EXPECT_EQ(2U, receiver->messageAllocator.pool.outstandingObjects);

    // Message[1]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[1]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[1]->resendTimeout.node.list);
    EXPECT_EQ(Receiver::Message::State::DROPPED, message[1]->getState());
    EXPECT_TRUE(bucket->messages.contains(&message[1]->bucketNode));
    EXPECT_EQ(2U, receiver->messageAllocator.pool.outstandingObjects);

    // Message[2]: No timeout
    EXPECT_EQ(&bucket->messageTimeouts.list,
              message[2]->messageTimeout.node.list);
    EXPECT_EQ(&bucket->resendTimeouts.list,
              message[2]->resendTimeout.node.list);
    EXPECT_TRUE(bucket->messages.contains(&message[2]->bucketNode));
    EXPECT_EQ(2U, receiver->messageAllocator.pool.outstandingObjects);
}

TEST_F(ReceiverTest, checkResendTimeouts)
{
    Receiver::Message* message[3];
    Receiver::MessageBucket* bucket = receiver->messageBuckets.buckets.at(0);
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messageAllocator.pool.construct(
            receiver, &mockDriver, 0, 10000, id, SocketAddress{22, 60001}, 5);
        bucket->resendTimeouts.setTimeout(&message[i]->resendTimeout);
    }

    // Message[0]: Normal timeout: Send Resends.
    // Message Packets
    //  0123456789
    // [1100001100]
    ASSERT_TRUE(message[0]->scheduled);
    ASSERT_EQ(5, message[0]->numUnscheduledPackets);
    ASSERT_EQ(Receiver::Message::State::IN_PROGRESS, message[0]->state);
    message[0]->resendTimeout.expirationCycleTime = 9999;
    message[0]->scheduledMessageInfo.bytesGranted = 10000;
    for (uint16_t i = 0; i < 2; ++i) {
        message[0]->setPacket(i, &mockPacket);
    }
    for (uint16_t i = 6; i < 8; ++i) {
        message[0]->setPacket(i, &mockPacket);
    }

    // Message[1]: Blocked on grants
    ASSERT_TRUE(message[1]->scheduled);
    ASSERT_EQ(Receiver::Message::State::IN_PROGRESS, message[0]->state);
    ASSERT_EQ(10000, message[1]->messageLength);
    message[1]->resendTimeout.expirationCycleTime = 10000;
    message[1]->scheduledMessageInfo.bytesGranted = 6000;
    message[1]->scheduledMessageInfo.bytesRemaining = 4000;

    // Message[2]: No timeout
    ASSERT_EQ(Receiver::Message::State::IN_PROGRESS, message[2]->state);
    message[2]->resendTimeout.expirationCycleTime = 10001;

    bucket->resendTimeouts.nextTimeout = 9999;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    char buf1[1024];
    char buf2[1024];
    Homa::Mock::MockDriver::MockPacket mockResendPacket1{buf1};
    Homa::Mock::MockDriver::MockPacket mockResendPacket2{buf2};

    EXPECT_CALL(mockDriver, allocPacket())
        .WillOnce(Return(&mockResendPacket1))
        .WillOnce(Return(&mockResendPacket2));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockResendPacket1),
                                       Eq(message[0]->source.ip), _))
        .Times(1);
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockResendPacket2),
                                       Eq(message[0]->source.ip), _))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockResendPacket1), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockResendPacket2), Eq(1)))
        .Times(1);

    // TEST CALL
    receiver->checkResendTimeouts(10000, bucket);

    EXPECT_EQ(message[2]->resendTimeout.expirationCycleTime,
              bucket->resendTimeouts.nextTimeout.load());

    // Message[0]: Normal timeout: resends
    EXPECT_EQ(10100, message[0]->resendTimeout.expirationCycleTime);
    Protocol::Packet::ResendHeader* header1 =
        static_cast<Protocol::Packet::ResendHeader*>(mockResendPacket1.payload);
    EXPECT_EQ(Protocol::Packet::RESEND, header1->common.opcode);
    EXPECT_EQ(message[0]->id, header1->common.messageId);
    EXPECT_EQ(2U, header1->index);
    EXPECT_EQ(4U, header1->num);
    EXPECT_EQ(sizeof(Protocol::Packet::ResendHeader), mockResendPacket1.length);
    Protocol::Packet::ResendHeader* header2 =
        static_cast<Protocol::Packet::ResendHeader*>(mockResendPacket2.payload);
    EXPECT_EQ(Protocol::Packet::RESEND, header2->common.opcode);
    EXPECT_EQ(message[0]->id, header2->common.messageId);
    EXPECT_EQ(8U, header2->index);
    EXPECT_EQ(2U, header2->num);
    EXPECT_EQ(sizeof(Protocol::Packet::ResendHeader), mockResendPacket2.length);

    // Message[1]: Blocked on grants
    EXPECT_EQ(10100, message[1]->resendTimeout.expirationCycleTime);

    // Message[2]: No timeout
    EXPECT_EQ(10001, message[2]->resendTimeout.expirationCycleTime);
}

TEST_F(ReceiverTest, trySendGrants)
{
    Receiver::Message* message[4];
    Receiver::ScheduledMessageInfo* info[4];
    for (uint32_t i = 0; i < 4; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messageAllocator.pool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader),
            10000 * (i + 1), id, SocketAddress{IP(100 + i), 60001},
            10 * (i + 1));
        {
            SpinLock::Lock lock_scheduler(receiver->schedulerMutex);
            receiver->schedule(message[i], lock_scheduler);
        }
        info[i] = &message[i]->scheduledMessageInfo;
        info[i]->priority = 10;  // bogus number that should be reset.
        info[i]->bytesGranted = 5000;
    }
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    Policy::Scheduled policy;

    //-------------------------------------------------------------------------
    // Test:
    //      - message[0] more grantable bytes than needed
    //      - message[0] full granted
    //      - message[1] min grants outstanding
    //      - more messages than overcommit level
    policy.maxScheduledPriority = 1;
    policy.degreeOvercommitment = 2;
    policy.minScheduledBytes = 5000;
    policy.maxScheduledBytes = 10000;
    info[0]->bytesRemaining -= 1000;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), _, _)).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->trySendGrants();

    EXPECT_EQ(1, info[0]->priority);
    EXPECT_EQ(info[0]->messageLength, info[0]->bytesGranted);
    EXPECT_EQ(nullptr, info[0]->peer);
    EXPECT_EQ(message[0]->id, header->common.messageId);
    EXPECT_EQ(0, info[1]->priority);
    EXPECT_EQ(5000, info[1]->bytesGranted);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - message[1] granted byte limit reached
    policy.maxScheduledPriority = 0;
    policy.degreeOvercommitment = 1;
    policy.minScheduledBytes = 5000;
    policy.maxScheduledBytes = 10000;
    info[1]->bytesRemaining -= 1000;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket), _, _)).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->trySendGrants();

    EXPECT_EQ(0, info[1]->priority);
    EXPECT_EQ(11000, info[1]->bytesGranted);
    EXPECT_EQ(message[1]->id, header->common.messageId);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - fewer priorities than overcommit/messages
    policy.maxScheduledPriority = 1;
    policy.degreeOvercommitment = 4;
    policy.minScheduledBytes = 5000;
    policy.maxScheduledBytes = 10000;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, sendPacket(_, _, _)).Times(0);

    receiver->trySendGrants();

    EXPECT_EQ(1, info[1]->priority);
    EXPECT_EQ(0, info[2]->priority);
    EXPECT_EQ(0, info[3]->priority);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - more priorities than overcommit/messages
    policy.maxScheduledPriority = 5;
    policy.degreeOvercommitment = 6;
    policy.minScheduledBytes = 5000;
    policy.maxScheduledBytes = 10000;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, sendPacket(_, _, _)).Times(0);

    receiver->trySendGrants();

    EXPECT_EQ(2, info[1]->priority);
    EXPECT_EQ(1, info[2]->priority);
    EXPECT_EQ(0, info[3]->priority);

    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, schedule)
{
    Receiver::Message* message[4];
    Receiver::ScheduledMessageInfo* info[4];
    IpAddress address[4] = {22, 33, 33, 22};
    int messageLength[4] = {2000, 3000, 1000, 4000};
    for (uint64_t i = 0; i < 4; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messageAllocator.pool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader),
            messageLength[i], id, SocketAddress{address[i], 60001}, 0);
        info[i] = &message[i]->scheduledMessageInfo;
    }

    SpinLock::Lock lock(receiver->schedulerMutex);

    //--------------------------------------------------------------------------
    // NEW PEER
    // <22>: [0](2000)
    EXPECT_EQ(2000U, info[0]->bytesRemaining);

    receiver->schedule(message[0], lock);

    EXPECT_EQ(&receiver->peerTable.at(IP(22)), info[0]->peer);
    EXPECT_EQ(message[0], &info[0]->peer->scheduledMessages.front());
    EXPECT_EQ(info[0]->peer, &receiver->scheduledPeers.front());

    //--------------------------------------------------------------------------
    // NEW PEER
    // <22>: [0](2000)
    // <33>: [1](3000)
    EXPECT_EQ(3000U, info[1]->bytesRemaining);

    receiver->schedule(message[1], lock);

    EXPECT_EQ(&receiver->peerTable.at(IP(33)), info[1]->peer);
    EXPECT_EQ(message[1], &info[1]->peer->scheduledMessages.front());
    EXPECT_EQ(info[1]->peer, &receiver->scheduledPeers.back());

    //--------------------------------------------------------------------------
    // PEER PRIORITY BUMP
    // <33>: [2](1000) -> [1](3000)
    // <22>: [0](2000)
    EXPECT_EQ(1000U, info[2]->bytesRemaining);

    receiver->schedule(message[2], lock);

    EXPECT_EQ(&receiver->peerTable.at(IP(33)), info[2]->peer);
    EXPECT_EQ(message[2], &info[2]->peer->scheduledMessages.front());
    EXPECT_EQ(info[2]->peer, &receiver->scheduledPeers.front());

    //--------------------------------------------------------------------------
    // PEER NO PRIORITY CHANGE
    // <33>: [2](1000) -> [1](3000)
    // <22>: [0](2000) -> [3](4000)
    EXPECT_EQ(4000U, info[3]->bytesRemaining);

    receiver->schedule(message[3], lock);

    EXPECT_EQ(&receiver->peerTable.at(IP(22)), info[3]->peer);
    EXPECT_EQ(message[3], &info[3]->peer->scheduledMessages.back());
    EXPECT_EQ(info[3]->peer, &receiver->scheduledPeers.back());
}

TEST_F(ReceiverTest, unschedule)
{
    Receiver::Message* message[5];
    Receiver::ScheduledMessageInfo* info[5];
    SpinLock::Lock lock(receiver->schedulerMutex);
    int messageLength[5] = {10, 20, 30, 10, 20};
    for (uint32_t i = 0; i < 5; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        IpAddress source = IP((i / 3) + 10);
        message[i] = receiver->messageAllocator.pool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader),
            messageLength[i], id, SocketAddress{source, 60001}, 0);
        info[i] = &message[i]->scheduledMessageInfo;
        receiver->schedule(message[i], lock);
    }
    auto& scheduledPeers = receiver->scheduledPeers;

    ASSERT_EQ(IP(10), message[0]->source.ip);
    ASSERT_EQ(IP(10), message[1]->source.ip);
    ASSERT_EQ(IP(10), message[2]->source.ip);
    ASSERT_EQ(IP(11), message[3]->source.ip);
    ASSERT_EQ(IP(11), message[4]->source.ip);
    ASSERT_EQ(&scheduledPeers.front(), &receiver->peerTable.at(IP(10)));
    ASSERT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(11)));

    // <10>: [0](10) -> [1](20) -> [2](30)
    // <11>: [3](10) -> [4](20)
    EXPECT_EQ(10, info[0]->bytesRemaining);
    EXPECT_EQ(20, info[1]->bytesRemaining);
    EXPECT_EQ(30, info[2]->bytesRemaining);
    EXPECT_EQ(10, info[3]->bytesRemaining);
    EXPECT_EQ(20, info[4]->bytesRemaining);

    //--------------------------------------------------------------------------
    // Remove message[4]; peer already at end.
    // <10>: [0](10) -> [1](20) -> [2](30)
    // <11>: [3](10)

    receiver->unschedule(message[4], lock);

    EXPECT_EQ(nullptr, info[4]->peer);
    EXPECT_EQ(&scheduledPeers.front(), &receiver->peerTable.at(IP(10)));
    EXPECT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(11)));
    EXPECT_EQ(3U, receiver->peerTable.at(IP(10)).scheduledMessages.size());
    EXPECT_EQ(1U, receiver->peerTable.at(IP(11)).scheduledMessages.size());

    //--------------------------------------------------------------------------
    // Remove message[1]; peer in correct position.
    // <10>: [0](10) -> [2](30)
    // <11>: [3](10)

    receiver->unschedule(message[1], lock);

    EXPECT_EQ(nullptr, info[1]->peer);
    EXPECT_EQ(&scheduledPeers.front(), &receiver->peerTable.at(IP(10)));
    EXPECT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(11)));
    EXPECT_EQ(2U, receiver->peerTable.at(IP(10)).scheduledMessages.size());
    EXPECT_EQ(1U, receiver->peerTable.at(IP(11)).scheduledMessages.size());

    //--------------------------------------------------------------------------
    // Remove message[0]; peer needs to be reordered.
    // <11>: [3](10)
    // <10>: [2](30)

    receiver->unschedule(message[0], lock);

    EXPECT_EQ(nullptr, info[0]->peer);
    EXPECT_EQ(&scheduledPeers.front(), &receiver->peerTable.at(IP(11)));
    EXPECT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(10)));
    EXPECT_EQ(1U, receiver->peerTable.at(IP(11)).scheduledMessages.size());
    EXPECT_EQ(1U, receiver->peerTable.at(IP(10)).scheduledMessages.size());

    //--------------------------------------------------------------------------
    // Remove message[3]; peer needs to be removed.
    // <10>: [2](30)

    receiver->unschedule(message[3], lock);

    EXPECT_EQ(nullptr, info[3]->peer);
    EXPECT_EQ(&scheduledPeers.front(), &receiver->peerTable.at(IP(10)));
    EXPECT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(10)));
    EXPECT_EQ(1U, receiver->peerTable.at(IP(10)).scheduledMessages.size());
    EXPECT_EQ(0U, receiver->peerTable.at(IP(11)).scheduledMessages.size());
}

TEST_F(ReceiverTest, updateSchedule)
{
    // 10 : [10]
    // 11 : [20][30]
    SpinLock::Lock lock(receiver->schedulerMutex);
    Receiver::Message* other[3];
    for (uint32_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        int messageLength = 10 * (i + 1);
        IpAddress source = IP(((i + 1) / 2) + 10);
        other[i] = receiver->messageAllocator.pool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader),
            10 * (i + 1), id, SocketAddress{source, 60001}, 0);
        receiver->schedule(other[i], lock);
    }
    Receiver::Message* message = receiver->messageAllocator.pool.construct(
        receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 100,
        Protocol::MessageId(42, 1), SocketAddress{11, 60001}, 0);
    receiver->schedule(message, lock);
    auto& peerTable = receiver->peerTable;
    ASSERT_EQ(&peerTable.at(IP(10)), other[0]->scheduledMessageInfo.peer);
    ASSERT_EQ(&peerTable.at(IP(11)), other[1]->scheduledMessageInfo.peer);
    ASSERT_EQ(&peerTable.at(IP(11)), other[2]->scheduledMessageInfo.peer);
    ASSERT_EQ(&peerTable.at(IP(11)), message->scheduledMessageInfo.peer);
    ASSERT_EQ(&receiver->scheduledPeers.front(), &peerTable.at(IP(10)));
    ASSERT_EQ(&receiver->scheduledPeers.back(), &peerTable.at(IP(11)));

    //--------------------------------------------------------------------------
    // Move message up within peer.
    // 10 : [10]
    // 11 : [20][XX][30]
    message->scheduledMessageInfo.bytesRemaining = 25;

    receiver->updateSchedule(message, lock);

    auto& scheduledPeers = receiver->scheduledPeers;
    EXPECT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(11)));
    Receiver::Peer* peer = &receiver->scheduledPeers.back();
    auto it = peer->scheduledMessages.begin();
    EXPECT_TRUE(
        std::next(receiver->peerTable.at(IP(11)).scheduledMessages.begin()) ==
        message->scheduledMessageInfo.peer->scheduledMessages.get(
            &message->scheduledMessageInfo.scheduledMessageNode));

    //--------------------------------------------------------------------------
    // Move message to front within peer.  No peer reordering.
    // 10 : [10]
    // 11 : [XX][20][30]
    message->scheduledMessageInfo.bytesRemaining = 10;

    receiver->updateSchedule(message, lock);

    EXPECT_EQ(&scheduledPeers.back(), &receiver->peerTable.at(IP(11)));
    EXPECT_EQ(receiver->peerTable.at(IP(11)).scheduledMessages.begin(),
              message->scheduledMessageInfo.peer->scheduledMessages.get(
                  &message->scheduledMessageInfo.scheduledMessageNode));

    //--------------------------------------------------------------------------
    // Reorder peer.
    // 11 : [XX][20][30]
    // 10 : [10]
    message->scheduledMessageInfo.bytesRemaining = 0;

    receiver->updateSchedule(message, lock);

    EXPECT_EQ(&scheduledPeers.front(), &receiver->peerTable.at(IP(11)));
    EXPECT_EQ(receiver->peerTable.at(IP(11)).scheduledMessages.begin(),
              message->scheduledMessageInfo.peer->scheduledMessages.get(
                  &message->scheduledMessageInfo.scheduledMessageNode));
}

}  // namespace
}  // namespace Core
}  // namespace Homa
