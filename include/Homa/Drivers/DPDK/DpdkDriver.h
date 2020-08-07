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

#ifndef HOMA_INCLUDE_HOMA_DRIVERS_DPDK_DPDKDRIVER_H
#define HOMA_INCLUDE_HOMA_DRIVERS_DPDK_DPDKDRIVER_H

#include <Homa/Driver.h>

#include <memory>

namespace Homa {
namespace Drivers {
namespace DPDK {

/**
 * A Driver for [DPDK](dpdk.org) communication. Simple packet send/receive style
 * interface. See Driver.h for more detail.
 *
 * This class is thread-safe.
 *
 * @sa Driver
 */
class DpdkDriver : public Driver {
  public:
    /**
     * Provides optional configuration information for the DpdkDriver instance.
     */
    struct Config {
        /// Override and set the Driver's maximum packet priority to this value.
        ///
        /// Default:
        ///   -1 indicates that no override should occur and Driver's default
        ///   value should be used.
        int HIGHEST_PACKET_PRIORITY_OVERRIDE = -1;
    };

    /**
     * Construct a DpdkDriver.
     *
     * This constructor should be used in the common case where Homa::Transport
     * has exclusive access to DPDK. Note: This call will initialize the DPDK
     * EAL with default values.
     *
     * @param ifname
     *      Selects which network interface to use for communication.
     * @param config
     *      Optional configuration parameters (see Config).
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    DpdkDriver(const char* ifname, const Config* const config = nullptr);

    /**
     * Construct a DpdkDriver and initialize the DPDK EAL using the provided
     * _argc_ and _argv_. [Advanced Usage]
     *
     * This constructor should be used if the caller wants to control what
     * parameters are provided to DPDK EAL initialization. The input parameters
     * _argc_ and _argv_ will be provided to rte_eal_init() directly. See the
     * DPDK documentation for initialization options.
     *
     * This constructor will maintain the currently set thread affinity by
     * overriding the default affinity set by rte_eal_init().
     *
     * @param port
     *      Selects which network interface to use for communication.
     * @param argc
     *      Parameter passed to rte_eal_init().
     * @param argv
     *      Parameter passed to rte_eal_init().
     * @param config
     *      Optional configuration parameters (see Config).
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    DpdkDriver(const char* ifname, int argc, char* argv[],
               const Config* const config = nullptr);

    /// Used to signal to the DpdkDriver constructor that the DPDK EAL should
    /// not be initialized.
    enum NoEalInit { NO_EAL_INIT };
    /**
     * Construct a DpdkDriver without initializing the DPDK EAL. [Advanced
     * Usage]
     *
     * This constructor is used when parts of the application other than the
     * DpdkDriver are using DPDK and the caller wants to take responsibility for
     * calling rte_eal_init(). The caller must ensure that rte_eal_init() is
     * called before calling this constructor.
     *
     * @param port
     *      Selects which network interface to use for communication.
     * @param _
     *      Parameter is used only to define this constructors alternate
     *      signature.
     * @param config
     *      Optional configuration parameters (see Config).
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    DpdkDriver(const char* ifname, NoEalInit _,
               const Config* const config = nullptr);

    /**
     * DpdkDriver Destructor.
     */
    virtual ~DpdkDriver();

    /// See Driver::allocPacket()
    virtual Packet* allocPacket();

    /// See Driver::sendPacket()
    virtual void sendPacket(Packet* packet, IpAddress destination,
                            int priority);

    /// See Driver::cork()
    virtual void cork();

    /// See Driver::uncork()
    virtual void uncork();

    /// See Driver::receivePackets()
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[],
                                    IpAddress sourceAddresses[]);

    /// See Driver::releasePackets()
    virtual void releasePackets(Packet* packets[], uint16_t numPackets);

    /// See Driver::getHighestPacketPriority()
    virtual int getHighestPacketPriority();

    /// See Driver::getMaxPayloadSize()
    virtual uint32_t getMaxPayloadSize();

    /// See Driver::getBandwidth()
    virtual uint32_t getBandwidth();

    /// See Driver::getLocalAddress()
    virtual IpAddress getLocalAddress();

    /// See Driver::getQueuedBytes();
    virtual uint32_t getQueuedBytes();

  private:
    // Forward declaration of implementation class.
    class Impl;

    /// The actual implementation of the DpdkDriver.  Hides the details of the
    /// driver from users of libDpdkDriver.
    std::unique_ptr<Impl> pImpl;

    // Disable copy and assign
    DpdkDriver(const DpdkDriver&) = delete;
    DpdkDriver& operator=(const DpdkDriver&) = delete;
};

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_DRIVERS_DPDK_DPDKDRIVER_H
