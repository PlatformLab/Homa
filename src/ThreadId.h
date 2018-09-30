/* Copyright (c) 2011-2018 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <cinttypes>
#include <string>

#ifndef HOMA_THREADID_H
#define HOMA_THREADID_H

namespace Homa {

/**
 * Provides a convenient way to get identifiers for threads.
 * This is better than std::this_thread::get_id() in a few ways:
 * - It returns to you an integer, not some opaque type.
 * - The integer it returns is usually short, which is nice for log messages.
 * - It's probably faster, since it uses gcc's __thread keyword.
 */
namespace ThreadId {

/**
 * A thread ID that will never be assigned to any thread.
 */
const uint64_t NONE = 0;

uint64_t getId();
void setName(const std::string& name);
std::string getName();

}  // namespace ThreadId
}  // namespace Homa

#endif  // HOMA_THREADID_H
