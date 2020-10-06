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

#include <atomic>
#include <cstring>
#include <random>
#include <unordered_map>

#include "CodeLocation.h"
#include "StringUtil.h"

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
    }

    /// Register the FakeNIC so it can receive packets.  Returns the newly
    /// registered FakeNIC's addressId.
    uint32_t registerNIC(FakeNIC* nic)
    {
        std::lock_guard<std::mutex> lock(mutex);
        uint32_t addressId = nextAddressId.fetch_add(1);
        IpAddress ipAddress{addressId};
        network.insert({ipAddress, nic});
        return addressId;
    }

    /// Remove the FakeNIC from the network.
    void deregisterNIC(uint32_t addressId)
    {
        std::lock_guard<std::mutex> lock(mutex);
        IpAddress ipAddress{addressId};
        network.erase(ipAddress);
    }

    /// Deliver the provide packet to the specified destination.
    void sendPacket(FakePacket* packet, int priority, IpAddress src,
                    IpAddress dst)
    {
        FakeNIC* nic = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (packetLossDistribution(gen) < packetLossRate) {
                return;
            }
            auto search = network.find(dst);
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
        dstPacket->sourceIp = src;
        assert(priority < NUM_PRIORITIES);
        assert(priority >= 0);
        nic->priorityQueue.at(priority).push_back(dstPacket);
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
    std::unordered_map<IpAddress, FakeNIC*, IpAddress::Hasher> network;

    /// Identifier for the next FakeDriver that "connects" to the FakeNetwork.
    std::atomic<uint32_t> nextAddressId;

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
 * See Driver::allocPacket()
 */
Driver::Packet*
FakeDriver::allocPacket()
{
    FakePacket* packet = new FakePacket();
    return &packet->base;
}

/**
 * See Driver::sendPacket()
 */
void
FakeDriver::sendPacket(Packet* packet, IpAddress destination, int priority)
{
    FakePacket* srcPacket = container_of(packet, &FakePacket::base);
    IpAddress srcAddress = getLocalAddress();
    IpAddress dstAddress = destination;
    fakeNetwork.sendPacket(srcPacket, priority, srcAddress, dstAddress);
    queueEstimator.signalBytesSent(packet->length);
}

/**
 * See Driver::receivePackets()
 */
uint32_t
FakeDriver::receivePackets(uint32_t maxPackets, Packet* receivedPackets[],
                           IpAddress sourceAddresses[])
{
    std::lock_guard<std::mutex> lock_nic(nic.mutex);
    uint32_t numReceived = 0;
    for (int i = NUM_PRIORITIES - 1; i >= 0; --i) {
        while (numReceived < maxPackets && !nic.priorityQueue.at(i).empty()) {
            FakePacket* fakePacket = nic.priorityQueue.at(i).front();
            nic.priorityQueue.at(i).pop_front();
            receivedPackets[numReceived] = &fakePacket->base;
            sourceAddresses[numReceived] = fakePacket->sourceIp;
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
        delete container_of(packets[i], &FakePacket::base);
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
IpAddress
FakeDriver::getLocalAddress()
{
    return IpAddress{localAddressId};
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
