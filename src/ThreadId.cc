/* Copyright (c) 2011-2018 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ThreadId.h"

#include "StringUtil.h"

#include <mutex>
#include <unordered_map>

namespace Homa {
namespace ThreadId {
namespace Internal {

/**
 * Thread-specific data holds the identifier for each thread.  It starts off
 * zero, but is set to a non-zero unique value the first time it is accessed.
 */
__thread uint64_t id = 0;

/**
 * Used to serialize access to #nextId.
 */
std::mutex mutex;

/**
 * The next thread identifier that has not already been used.
 */
uint64_t nextId = 1;

/**
 * A map from thread ID to thread name.
 * Not all threads may be present in this map; only those that have had their
 * name set will be found here.
 */
std::unordered_map<uint64_t, std::string> threadNames;

/**
 * Pick a unique value to use as the thread identifier for the current
 * thread. This value is saved in the thread-specific variable #id.
 */
void
assign()
{
    std::lock_guard<std::mutex> lockGuard(mutex);
    id = nextId;
    ++nextId;
}

}  // namespace Internal

/**
 * Return a unique identifier associated with this thread.  The
 * return value has two properties:
 * - It will never be zero.
 * - It will be unique for this thread (i.e., no other thread has ever
 *   been returned this value or ever will be returned this value)
 */
uint64_t
getId()
{
    if (Internal::id == 0)
        Internal::assign();
    return Internal::id;
}

/**
 * Set the friendly name for the current thread.
 * This can be later retrieved with getName().
 * Calling setName with an empty string will reset the thread to its default
 * name.
 */
void
setName(const std::string& name)
{
    // get the thread ID before locking to avoid deadlock
    uint64_t id = getId();
    std::lock_guard<std::mutex> lockGuard(Internal::mutex);
    if (name.empty())
        Internal::threadNames.erase(id);
    else
        Internal::threadNames[id] = name;
}

/**
 * Get the friendly name for the current thread.
 * This is useful in messages to users.
 *
 * You should arrange for setName() to be called when the thread is
 * created; otherwise you'll see an unhelpful name like "thread 3".
 */
std::string
getName()
{
    // get the thread ID before locking to avoid deadlock
    uint64_t id = getId();
    std::lock_guard<std::mutex> lockGuard(Internal::mutex);
    auto it = Internal::threadNames.find(id);
    if (it == Internal::threadNames.end())
        return StringUtil::format("thread %lu", id);
    else
        return it->second;
}

}  // namespace ThreadId
}  // namespace Homa
