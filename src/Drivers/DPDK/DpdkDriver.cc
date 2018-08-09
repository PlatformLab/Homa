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

#include "DpdkDriver.h"

#include "DpdkDriverImpl.h"

namespace Homa {
namespace Drivers {
namespace DPDK {

DpdkDriver*
DpdkDriver::newDpdkDriver(int port)
{
    return new DpdkDriverImpl(port);
}

DpdkDriver*
DpdkDriver::newDpdkDriver(int port, int argc, char* argv[])
{
    return new DpdkDriverImpl(port, argc, argv);
}

DpdkDriver*
DpdkDriver::newDpdkDriver(int port, DpdkDriver::NoEalInit _)
{
    return new DpdkDriverImpl(port, _);
}

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa