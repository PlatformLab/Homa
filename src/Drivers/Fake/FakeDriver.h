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

#ifndef HOMA_DRIVERS_FAKE_FAKEDRIVER_H
#define HOMA_DRIVERS_FAKE_FAKEDRIVER_H

#include <array>
#include <chrono>
#include <deque>
#include <mutex>

#include <Homa/Driver.h>
#include <Homa/Drivers/Util/QueueEstimator.h>

namespace Homa {
namespace Drivers {
namespace Fake {

/// Number of priorities this FakeDriver/FakeNetwork supports.
const int NUM_PRIORITIES = 8;

/// Maximum number of bytes a packet can hold.
const uint32_t MAX_PAYLOAD_SIZE = 1500;

/// A set of methods to contol the underlying FakeNetwork's behavior.
namespace FakeNetworkConfig {
/**
 * Configure the FakeNetwork to drop packets at the specified loss rate.
 *
 * E.g. setting a rate of 1.0 will cause all packets to be dropped; a rate
 * of 0.5 will drop the packets half the time.
 */
void setPacketLossRate(double lossRate);
}  // namespace FakeNetworkConfig

/**
 * Represents a packet of data that can be send or is received through a
 * FakeDriver over a FakeNetwork.
 *
 * @sa Driver::Packet
 */
class FakePacket : public Driver::Packet {
  public:
    /**
     * FakePacket constructor.
     *
     * @param maxPayloadSize
     *      The maximum number of bytes this packet can hold.
     */
    explicit FakePacket()
        : Packet(buf, 0)
    {}

    /**
     * Copy constructor.
     */
    FakePacket(const FakePacket& other)
        : Packet(buf, other.length)
    {
        address = other.address;
        priority = other.priority;
        memcpy(buf, other.buf, MAX_PAYLOAD_SIZE);
    }

    virtual ~FakePacket() {}

    /// see Driver::Packet::getMaxPayloadSize()
    virtual uint16_t getMaxPayloadSize()
    {
        return MAX_PAYLOAD_SIZE;
    }

  private:
    /// Raw storage for this packets payload.
    char buf[MAX_PAYLOAD_SIZE];

    // Disable Assignment
    FakePacket& operator=(const FakePacket&) = delete;
};

/// Holds the incoming packets for a particular driver.
struct FakeNIC {
    /// Monitor lock for the FakeNIC structure.
    std::mutex mutex;

    /// A set of incoming packets queued by priority.
    std::array<std::deque<FakePacket*>, NUM_PRIORITIES> priorityQueue;

    FakeNIC();
    ~FakeNIC();
};

/**
 * A fake driver that sends and receives datagrams using a fake network.
 *
 * Used in tests to allow multiple instances of Homa::Transport to send and
 * receive datagrams without actually using the network.  Instances of
 * Homa::Transport must be as part of a single process for FakeDriver to work.
 */
class FakeDriver : public Driver {
  public:
    FakeDriver();
    /**
     * FakeDriver destructor.
     */
    virtual ~FakeDriver();

    virtual Address* getAddress(std::string const* const addressString);
    virtual Address* getAddress(Driver::Address::Raw const* const rawAddress);
    virtual Packet* allocPacket();
    virtual void sendPacket(Packet* packet);
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[]);
    virtual void releasePackets(Packet* packets[], uint16_t numPackets);
    virtual int getHighestPacketPriority();
    virtual uint32_t getMaxPayloadSize();
    virtual uint32_t getBandwidth();
    virtual Address* getLocalAddress();
    virtual uint32_t getQueuedBytes();

  private:
    /// Identifier for this driver on the fake network.
    uint64_t localAddressId;

    /// Holds the incoming packets for this driver.
    FakeNIC nic;

    /// Tracks the size of the NIC's transmit queue.
    Util::QueueEstimator<std::chrono::steady_clock> queueEstimator;

    // Disable copy and assign
    FakeDriver(const FakeDriver&) = delete;
    FakeDriver& operator=(const FakeDriver&) = delete;
};

}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_FAKE_FAKEDRIVER_H
