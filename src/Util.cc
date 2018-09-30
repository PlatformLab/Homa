/* Copyright (c) 2009-2018, Stanford University
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

#include "Homa/Util.h"

#include "Homa/Exception.h"

#include "CodeLocation.h"
#include "StringUtil.h"

#include <cinttypes>
#include <sstream>

namespace Homa {
namespace Util {

/**
 * Helper function to call __cxa_demangle. Has internal linkage.
 * Handles the C-style memory management required.
 * Returns a std::string with the long human-readable name of the
 * type.
 * @param name
 *      The "name" of the type that needs to be demangled.
 * @throw FatalError
 *      The short internal type name could not be converted.
 */
// This was taken from the RAMCloud project.
std::string
demangle(const char* name)
{
    int status;
    char* res = abi::__cxa_demangle(name, NULL, NULL, &status);
    if (status != 0) {
        throw FatalError(HERE_STR,
                         "cxxabi.h's demangle() could not demangle type");
    }
    // contruct a string with a copy of the C-style string returned.
    std::string ret(res);
    // __cxa_demangle would have used realloc() to allocate memory
    // which should be freed now.
    free(res);
    return ret;
}

/**
 * Return (potentially multi-line) string hex dump of a binary buffer in
 * 'hexdump -C' style.
 * Note that this exceeds 80 characters due to 64-bit offsets.
 */
// This was taken from the RAMCloud project.
std::string
hexDump(const void* buf, uint64_t bytes)
{
    const unsigned char* cbuf = reinterpret_cast<const unsigned char*>(buf);
    uint64_t i, j;

    std::ostringstream output;
    for (i = 0; i < bytes; i += 16) {
        char offset[17];
        char hex[16][3];
        char ascii[17];

        std::snprintf(offset, sizeof(offset), "%016" PRIx64, i);
        offset[sizeof(offset) - 1] = '\0';

        for (j = 0; j < 16; j++) {
            if ((i + j) >= bytes) {
                snprintf(hex[j], sizeof(hex[0]), "  ");
                ascii[j] = '\0';
            } else {
                snprintf(hex[j], sizeof(hex[0]), "%02x", cbuf[i + j]);
                hex[j][sizeof(hex[0]) - 1] = '\0';
                if (isprint(static_cast<int>(cbuf[i + j])))
                    ascii[j] = cbuf[i + j];
                else
                    ascii[j] = '.';
            }
        }
        ascii[sizeof(ascii) - 1] = '\0';

        output << StringUtil::format(
            "%s  %s %s %s %s %s %s %s %s  %s %s %s %s %s %s %s %s  "
            "|%s|\n",
            offset, hex[0], hex[1], hex[2], hex[3], hex[4], hex[5], hex[6],
            hex[7], hex[8], hex[9], hex[10], hex[11], hex[12], hex[13], hex[14],
            hex[15], ascii);
    }
    return output.str();
}

}  // namespace Util
}  // namespace Homa
