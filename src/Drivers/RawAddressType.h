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

#ifndef HOMA_DRIVERS_RAWADDRESSTYPE_H
#define HOMA_DRIVERS_RAWADDRESSTYPE_H

namespace Homa {
namespace Drivers {

/**
 * Identifies a particular raw serialized byte-format for a Driver::Address
 * supported by this project.  The types are enumerated here in one place to
 * ensure drivers do have overlapping type identifiers.  New drivers that wish
 * to claim a type id should add an entry to this enum.
 *
 * @sa Driver::Address::Raw
 */
enum RawAddressType {
    FAKE = 0,
    MAC = 1,
};

}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_DRIVERS_RAWADDRESSTYPE_H
