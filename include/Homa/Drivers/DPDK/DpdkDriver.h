/* Copyright (c) 2018, Stanford University
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

#ifndef HOMA_DRIVERS_DPDK_DPDKDRIVER_H
#define HOMA_DRIVERS_DPDK_DPDKDRIVER_H

#include "Homa/Driver.h"

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
     * Create and return a pointer to a DpdkDriver.
     *
     * This factory function should be used in the common case where the
     * DpdkDriver is the only part the application using DPDK. Note: This call
     * will initialize the DPDK EAL with default values.
     *
     * The caller is responisble for calling `delete` on the returned Driver
     * when the driver is no longer needed.
     *
     * @param port
     *      Selects which physical port to use for communication.
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    static DpdkDriver* newDpdkDriver(int port);

    /**
     * Create and return a pointer to a DpdkDriver and initilize the DPDK EAL
     * using the provided _argc_ and _argv_. [Advanced Usage]
     *
     * This factory function should be used if the caller wants to control what
     * parameters are provided to DPDK EAL initialization. The input parameters
     * _argc_ and _argv_ will be provided to rte_eal_init() directly. See the
     * DPDK documentation for initilization options.
     *
     * This factory function will maintain the currently set thread affinity by
     * overriding the default affinity set by rte_eal_init().
     *
     * The caller is responisble for calling `delete` on the returned Driver
     * when the driver is no longer needed.
     *
     * @param port
     *      Selects which physical port to use for communication.
     * @param argc
     *      Parameter passed to rte_eal_init().
     * @param argv
     *      Parameter passed to rte_eal_init().
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    static DpdkDriver* newDpdkDriver(int port, int argc, char* argv[]);

    /// Used to signal to the DpdkDriver constructor that the DPDK EAL should
    /// not be initialized.
    enum NoEalInit { NO_EAL_INIT };
    /**
     * Create and return a pointer to a DpdkDriver without initilizing the DPDK
     * EAL. [Advanced Usage]
     *
     * This factory function is used when parts of the application other than
     * the DpdkDriver are using DPDK and the caller wants to take responsiblity
     * for calling rte_eal_init(). The caller must ensure that rte_eal_init() is
     * called before calling this constructor.
     *
     * The caller is responisble for calling `delete` on the returned Driver
     * when the driver is no longer needed.
     *
     * @param port
     *      Selects which physical port to use for communication.
     * @param _
     *      Parameter is used only to define this constructors alternate
     *      signature.
     * @throw DriverInitFailure
     *      Thrown if DpdkDriver fails to initialize for any reason.
     */
    static DpdkDriver* newDpdkDriver(int port, NoEalInit _);

    /// See Driver::getAddress()
    virtual Driver::Address* getAddress(
        std::string const* const addressString) = 0;

    /// See Driver::allocPacket()
    virtual Packet* allocPacket() = 0;

    /// See Driver::sendPackets()
    virtual void sendPackets(Packet* packets[], uint16_t numPackets) = 0;

    /// See Driver::receivePackets()
    virtual uint32_t receivePackets(uint32_t maxPackets,
                                    Packet* receivedPackets[]) = 0;

    /// See Driver::releasePackets()
    virtual void releasePackets(Packet* packets[], uint16_t numPackets) = 0;

    /// See Driver::getHighestPacketPriority()
    virtual int getHighestPacketPriority() = 0;

    /// See Driver::getMaxPayloadSize()
    virtual uint32_t getMaxPayloadSize() = 0;

    /// See Driver::getBandwidth()
    virtual uint32_t getBandwidth() = 0;

    /// See Driver::getLocalAddress()
    virtual Driver::Address* getLocalAddress() = 0;

    /**
     * Override the local address provided to by the NIC. Used in testing when
     * the virtual NICs address is not actually routable.
     *
     * @param addressString
     *      String representing the local address that this driver should use.
     */
    virtual void setLocalAddress(std::string const* const addressString) = 0;

  private:
};

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_DPDK_DPDKDRIVER_H
