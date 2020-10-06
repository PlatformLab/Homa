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

#include <Homa/Driver.h>

#include "StringUtil.h"

namespace Homa {

std::string
IpAddress::toString(IpAddress address)
{
    uint32_t ip = address.addr;
    return StringUtil::format("%d.%d.%d.%d", (ip >> 24) & 0xff,
                              (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}

IpAddress
IpAddress::fromString(const char* addressStr)
{
    unsigned int b0, b1, b2, b3;
    sscanf(addressStr, "%u.%u.%u.%u", &b0, &b1, &b2, &b3);
    return IpAddress{(b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3};
}

}  // namespace Homa
