/* Copyright (c) 2011-2020, Stanford University
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

#ifndef HOMA_DRIVERS_DPDK_MACADDRESS_H
#define HOMA_DRIVERS_DPDK_MACADDRESS_H

#include <Homa/Driver.h>

namespace Homa {
namespace Drivers {
namespace DPDK {

/**
 * A container for an Ethernet hardware address.
 */
struct MacAddress {
    explicit MacAddress(const uint8_t raw[6]);
    explicit MacAddress(const char* macStr);
    MacAddress(const MacAddress&) = default;
    std::string toString() const;
    bool isNull() const;

    /**
     * Equality function for MacAddress, for use in std::unordered_maps etc.
     */
    bool operator==(const MacAddress& other) const
    {
        return (*(uint32_t*)(address + 0) == *(uint32_t*)(other.address + 0)) &&
               (*(uint16_t*)(address + 4) == *(uint16_t*)(other.address + 4));
    }

    /// The raw bytes of the MAC address.
    uint8_t address[6];
};

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_DPDK_MACADDRESS_H
