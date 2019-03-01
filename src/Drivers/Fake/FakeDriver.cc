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

#include "FakeDriver.h"

#include "FakeAddress.h"

#include <atomic>
#include <cstring>
#include <unordered_map>

namespace Homa {
namespace Drivers {
namespace Fake {

/**
 * A fake network that allows a FakeDriver instances to pass around datagrams.
 */
static struct FakeNetwork {
    /// Monitor lock for the entire FakeNetwork structure.
    std::mutex mutex;

    /// Holds all the packets being sent through the fake network.
    std::unordered_map<uint64_t, FakeNIC*> network;

    /// Collection of FakeAddress objects that can be reused.
    std::unordered_map<uint64_t, FakeAddress*> addressCache;

    /// Constructor.
    FakeNetwork()
        : mutex()
        , network()
        , addressCache()
    {}

    /// Destructor;
    ~FakeNetwork()
    {
        std::lock_guard<std::mutex> lock_network(mutex);
        for (auto it = network.begin(); it != network.end(); ++it) {
            delete it->second;
        }
        // Clean up addressCache
        for (auto it = addressCache.begin(); it != addressCache.end(); ++it) {
            delete it->second;
        }
    }

    /// Return a pointer to a FakeAddress for a given addressId.
    FakeAddress* getAddress(uint64_t addressId)
    {
        FakeAddress* addr;
        auto it = addressCache.find(addressId);
        if (it == addressCache.end()) {
            FakeAddress* fakeAddr = new FakeAddress(addressId);
            addressCache[addressId] = fakeAddr;
            addr = fakeAddr;
        } else {
            addr = it->second;
        }
        return addr;
    }

} fakeNetwork;

/// The FakeAddress identifier for the next FakeDriver that "connects" to
/// the FakeNetwork.
static std::atomic<uint64_t> nextAddressId(1);

/**
 * FakeNIC constructor.
 */
FakeNIC::FakeNIC()
    : mutex()
    , priorityQueue()
{}

/**
 * FakeNIC destructor.
 */
FakeNIC::~FakeNIC()
{
    std::lock_guard<std::mutex> lock_nic(mutex);
    for (int i = 0; i < NUM_PRIORITIES; ++i) {
        while (!priorityQueue.at(i).empty()) {
            FakePacket* fakePacket = priorityQueue.at(i).front();
            delete fakePacket;
            priorityQueue.at(i).pop_front();
        }
    }
}

/**
 * FakeDriver Constructor.
 */
FakeDriver::FakeDriver()
    : localAddressId()
    , nic()
{
    std::lock_guard<std::mutex> lock(fakeNetwork.mutex);
    localAddressId = nextAddressId.fetch_add(1);
    fakeNetwork.network.insert({localAddressId, &nic});
}

/**
 * FakeDriver Destructor.
 */
FakeDriver::~FakeDriver()
{
    std::lock_guard<std::mutex> lock_network(fakeNetwork.mutex);
    fakeNetwork.network.erase(localAddressId);
}

/**
 * See Driver::getAddress()
 */
Driver::Address*
FakeDriver::getAddress(std::string const* const addressString)
{
    std::lock_guard<std::mutex> lock(fakeNetwork.mutex);
    uint64_t addressId = FakeAddress::toAddressId(addressString->c_str());
    return fakeNetwork.getAddress(addressId);
}

/**
 * See Driver::getAddress()
 */
Driver::Address*
FakeDriver::getAddress(Driver::Address::Raw const* const rawAddress)
{
    std::lock_guard<std::mutex> lock(fakeNetwork.mutex);
    FakeAddress address(rawAddress);
    return fakeNetwork.getAddress(address.address);
}

/**
 * See Driver::allocPacket()
 */
Driver::Packet*
FakeDriver::allocPacket()
{
    std::lock_guard<std::mutex> lock(fakeNetwork.mutex);
    FakePacket* packet = new FakePacket();
    return packet;
}

/**
 * See Driver::sendPackets()
 */
void
FakeDriver::sendPackets(Packet* packets[], uint16_t numPackets)
{
    for (uint16_t i = 0; i < numPackets; ++i) {
        FakePacket* srcPacket = static_cast<FakePacket*>(packets[i]);
        FakeAddress* dstAddress = static_cast<FakeAddress*>(srcPacket->address);
        FakeNIC* nic = nullptr;
        {
            std::lock_guard<std::mutex> lock_network(fakeNetwork.mutex);
            auto search = fakeNetwork.network.find(dstAddress->address);
            if (search == fakeNetwork.network.end()) {
                continue;
            } else {
                nic = search->second;
                nic->mutex.lock();
            }
        }
        assert(nic != nullptr);
        std::lock_guard<std::mutex> lock_nic(nic->mutex, std::adopt_lock);
        FakePacket* dstPacket = new FakePacket(*srcPacket);
        dstPacket->address = getLocalAddress();
        assert(dstPacket->priority < NUM_PRIORITIES);
        assert(dstPacket->priority >= 0);
        nic->priorityQueue.at(dstPacket->priority).push_back(dstPacket);
    }
}

/**
 * See Driver::receivePackets()
 */
uint32_t
FakeDriver::receivePackets(uint32_t maxPackets, Packet* receivedPackets[])
{
    std::lock_guard<std::mutex> lock_nic(nic.mutex);
    uint32_t numReceived = 0;
    for (int i = NUM_PRIORITIES - 1; i >= 0; --i) {
        while (numReceived < maxPackets && !nic.priorityQueue.at(i).empty()) {
            receivedPackets[numReceived] = nic.priorityQueue.at(i).front();
            nic.priorityQueue.at(i).pop_front();
            numReceived++;
        }
    }
    return numReceived;
}

/**
 * See Driver::releasePackets()
 */
void
FakeDriver::releasePackets(Packet* packets[], uint16_t numPackets)
{
    for (uint16_t i = 0; i < numPackets; ++i) {
        FakePacket* packet = static_cast<FakePacket*>(packets[i]);
        delete packet;
    }
}

/**
 * See Driver::getHighestPacketPriority()
 */
int
FakeDriver::getHighestPacketPriority()
{
    return NUM_PRIORITIES - 1;
}

/**
 * See Driver::getMaxPayloadSize()
 */
uint32_t
FakeDriver::getMaxPayloadSize()
{
    return MAX_PAYLOAD_SIZE;
}

/**
 * See Driver::getBandwidth()
 */
uint32_t
FakeDriver::getBandwidth()
{
    return 0;
}

/**
 * See Driver::getLocalAddress()
 */
Driver::Address*
FakeDriver::getLocalAddress()
{
    std::lock_guard<std::mutex> lock(fakeNetwork.mutex);
    return fakeNetwork.getAddress(localAddressId);
}

}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa
