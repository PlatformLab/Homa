/* Copyright (c) 2011-2018, Stanford University
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

#include "FakeAddress.h"

#include "CodeLocation.h"
#include "StringUtil.h"

#include <cstdlib>

namespace Homa {
namespace Drivers {
namespace Fake {

/**
 * Create a new address from the given address identifier.
 *
 * @param addressId
 *      Identifier of the address to be created.
 */
FakeAddress::FakeAddress(const uint64_t addressId)
    : Address()
    , address(addressId)
{}

/**
 * Create a new address from a string representation.
 *
 * @param addressStr
 *      String for the address identifer; a positive number in base 10.
 * @throw Exception
 *      The format of the given addressStr is invalid.
 */
FakeAddress::FakeAddress(const char* addressStr)
    : Address()
    , address(toAddressId(addressStr))
{}

/**
 * Create a new copy of the provided FakeAddress.
 *
 * @param other
 *      FakeAddress to be copied.
 */
FakeAddress::FakeAddress(const FakeAddress& other)
    : Address()
    , address(other.address)
{}

/**
 * Return the string representation of this address.
 */
inline std::string
FakeAddress::toString() const
{
    char buf[21];
    snprintf(buf, sizeof(buf), "%lu", address);
    return buf;
}

/**
 * Return the address identifier for the given address string.
 */
inline uint64_t
FakeAddress::toAddressId(const char* addressStr)
{
    char* end;
    uint64_t address = std::strtoul(addressStr, &end, 10);
    if (address == 0) {
        throw BadAddress(
            HERE_STR, StringUtil::format("Bad address string: %s", addressStr));
    }
    return address;
}

}  // namespace Fake
}  // namespace Drivers
}  // namespace Homa
