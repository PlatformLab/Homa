/* Copyright (c) 2011-2019, Stanford University
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

#include "MacAddress.h"

#include "StringUtil.h"

#include "../../CodeLocation.h"
#include "../RawAddressType.h"

namespace Homa {
namespace Drivers {
namespace DPDK {

/**
 * Create a new address from 6 bytes.
 * @param raw
 *      The raw bytes.
 */
MacAddress::MacAddress(const uint8_t raw[6])
{
    memcpy(address, raw, 6);
}

/**
 * Create a new address from a string representation.
 * @param macStr
 *      A MAC address like "01:23:45:67:89:ab". Uppercase is also allowed.
 * @throw Exception
 *      The format of the given \a macStr is invalid. If this is thrown,
 *      the contents of the address will be left unmodified.
 */
MacAddress::MacAddress(const char* macStr)
{
    unsigned int bytes[6];
    int r = sscanf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",  // NOLINT
                   &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4],
                   &bytes[5]);
    if (r != 6 || macStr[17] != '\0')
        throw BadAddress(HERE_STR,
                         StringUtil::format("Bad MAC address: %s", macStr));
    for (uint32_t i = 0; i < 6; ++i)
        address[i] = Util::downCast<uint8_t>(bytes[i]);
}

/**
 * Create a new address from a given address in its raw byte format.
 * @param raw
 *      The raw bytes format.
 *
 * @sa Driver::Address::Raw
 */
MacAddress::MacAddress(const Driver::WireFormatAddress* const wireAddress)
{
    if (wireAddress->type != RawAddressType::MAC) {
        throw BadAddress(HERE_STR, "Bad address: Raw format is not type MAC");
    }
    static_assert(sizeof(wireAddress->bytes) >= 6);
    memcpy(address, wireAddress->bytes, 6);
}

/**
 * Create a new address given the Driver::Address representation.
 *
 * @param addr
 *      The Driver::Address representation of an address.
 */
MacAddress::MacAddress(const Driver::Address addr)
{
    memcpy(address, &addr, 6);
}

/**
 * Return the string representation of this address.
 */
std::string
MacAddress::toString() const
{
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", address[0],
             address[1], address[2], address[3], address[4], address[5]);
    return buf;
}

/**
 * Serialized this address into a wire format.
 *
 * @param[out] wireAddress
 *      WireFormatAddress object to which the this address is serialized.
 */
void
MacAddress::toWireFormat(Driver::WireFormatAddress* wireAddress) const
{
    static_assert(sizeof(wireAddress->bytes) >= 6);
    memcpy(wireAddress->bytes, address, 6);
    wireAddress->type = RawAddressType::MAC;
}

/**
 * Return a Driver::Address representation of this address.
 */
Driver::Address
MacAddress::toAddress() const
{
    Driver::Address addr = 0;
    memcpy(&addr, address, 6);
    return addr;
}

/**
 * @return
 *      True if the MacAddress consists of all zero bytes, false if not.
 */
bool
MacAddress::isNull() const
{
    if (address[0] == 0 && address[1] == 0 && address[2] == 0 &&
        address[3] == 0 && address[4] == 0 && address[5] == 0)
        return true;
    else
        return false;
}

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa
