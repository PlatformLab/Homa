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

#include <Homa/Driver.h>

#include <array>
#include <deque>
#include <mutex>

namespace Homa {
namespace Drivers {
namespace Fake {

/// Number of priorities this FakeDriver/FakeNetwork supports.
const int NUM_PRIORITIES = 8;

/// Maximum number of bytes a packet can hold.
const uint32_t MAX_PAYLOAD_SIZE = 1500;

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

/// Holds the incomming packets for a particular driver.
struct FakeNIC {
    /// Monitor lock for the FakeNIC structure.
    std::mutex mutex;

    /// A set of incomming packets queued by priority.
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

    Address* getAddress(std::string const* const addressString);
    Packet* allocPacket();
    void sendPackets(Packet* packets[], uint16_t numPackets);
    uint32_t receivePackets(uint32_t maxPackets, Packet* receivedPackets[]);
    void releasePackets(Packet* packets[], uint16_t numPackets);
    int getHighestPacketPriority();
    uint32_t getMaxPayloadSize();
    uint32_t getBandwidth();
    Address* getLocalAddress();

  private:
    /// Identifier for this driver on the fake network.
    uint64_t localAddressId;

    /// Holds the incomming packets for this driver.
    FakeNIC nic;

    // Disable copy and assign
    FakeDriver(const FakeDriver&) = delete;
    FakeDriver& operator=(const FakeDriver&) = delete;
};

}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_FAKE_FAKEDRIVER_H
