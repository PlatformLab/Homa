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
#include <random>
#include <unordered_map>

namespace Homa {
namespace Drivers {
namespace Fake {

// Used to generate random numbers;
std::random_device rd;
std::mt19937 gen(rd());

/**
 * A fake network that allows a FakeDriver instances to pass around datagrams.
 */
static class FakeNetwork {
  public:
    /// Constructor.
    FakeNetwork()
        : mutex()
        , network()
        , addressCache()
        , nextAddressId(1)
        , packetLossRate(0)
        , packetLossDistribution(0.0, 1.0)
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
        std::lock_guard<std::mutex> lock(mutex);
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

    /// Register the FakeNIC so it can receive packets.  Returns the newly
    /// registered FakeNIC's addressId.
    uint64_t registerNIC(FakeNIC* nic)
    {
        std::lock_guard<std::mutex> lock(mutex);
        uint64_t addressId = nextAddressId.fetch_add(1);
        network.insert({addressId, nic});
        return addressId;
    }

    /// Remove the FakeNIC from the network.
    void deregisterNIC(uint64_t addressId)
    {
        std::lock_guard<std::mutex> lock(mutex);
        network.erase(addressId);
    }

    /// Deliver the provide packet to the specified destination.
    void sendPacket(FakePacket* packet, FakeAddress* src, FakeAddress* dst)
    {
        FakeNIC* nic = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (packetLossDistribution(gen) < packetLossRate) {
                return;
            }
            auto search = network.find(dst->address);
            if (search == network.end()) {
                return;
            } else {
                nic = search->second;
                nic->mutex.lock();
            }
        }
        assert(nic != nullptr);
        std::lock_guard<std::mutex> lock_nic(nic->mutex, std::adopt_lock);
        FakePacket* dstPacket = new FakePacket(*packet);
        dstPacket->address = src;
        assert(dstPacket->priority < NUM_PRIORITIES);
        assert(dstPacket->priority >= 0);
        nic->priorityQueue.at(dstPacket->priority).push_back(dstPacket);
    }

    void setPacketLossRate(double lossRate)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (lossRate > 1.0) {
            packetLossRate = 1.0;
        } else if (lossRate < 0.0) {
            packetLossRate = 0.0;
        } else {
            packetLossRate = lossRate;
        }
    }

  private:
    /// Monitor lock for the entire FakeNetwork structure.
    std::mutex mutex;

    /// Holds all the packets being sent through the fake network.
    std::unordered_map<uint64_t, FakeNIC*> network;

    /// Collection of FakeAddress objects that can be reused.
    std::unordered_map<uint64_t, FakeAddress*> addressCache;

    /// The FakeAddress identifier for the next FakeDriver that "connects" to
    /// the FakeNetwork.
    std::atomic<uint64_t> nextAddressId;

    /// Rate at which packets should be dropped when sent over this network.
    double packetLossRate;

    /// Distribution from which we will determine if a packet is dropped.
    std::uniform_real_distribution<> packetLossDistribution;

} fakeNetwork;

void
FakeNetworkConfig::setPacketLossRate(double lossRate)
{
    fakeNetwork.setPacketLossRate(lossRate);
}

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
    , queueEstimator(getBandwidth())
{
    localAddressId = fakeNetwork.registerNIC(&nic);
}

/**
 * FakeDriver Destructor.
 */
FakeDriver::~FakeDriver()
{
    fakeNetwork.deregisterNIC(localAddressId);
}

/**
 * See Driver::getAddress()
 */
Driver::Address*
FakeDriver::getAddress(std::string const* const addressString)
{
    uint64_t addressId = FakeAddress::toAddressId(addressString->c_str());
    return fakeNetwork.getAddress(addressId);
}

/**
 * See Driver::getAddress()
 */
Driver::Address*
FakeDriver::getAddress(Driver::Address::Raw const* const rawAddress)
{
    FakeAddress address(rawAddress);
    return fakeNetwork.getAddress(address.address);
}

/**
 * See Driver::allocPacket()
 */
Driver::Packet*
FakeDriver::allocPacket()
{
    FakePacket* packet = new FakePacket();
    return packet;
}

/**
 * See Driver::sendPacket()
 */
void
FakeDriver::sendPacket(Packet* packet)
{
    FakePacket* srcPacket = static_cast<FakePacket*>(packet);
    FakeAddress* srcAddress = static_cast<FakeAddress*>(getLocalAddress());
    FakeAddress* dstAddress = static_cast<FakeAddress*>(srcPacket->address);
    fakeNetwork.sendPacket(srcPacket, srcAddress, dstAddress);
    queueEstimator.signalBytesSent(packet->length);
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
    // 10 Gbps
    return 10000;
}

/**
 * See Driver::getLocalAddress()
 */
Driver::Address*
FakeDriver::getLocalAddress()
{
    return fakeNetwork.getAddress(localAddressId);
}

/**
 * See Driver::getQueuedBytes()
 */
uint32_t
FakeDriver::getQueuedBytes()
{
    return queueEstimator.getQueuedBytes();
}

}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa
