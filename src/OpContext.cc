/* Copyright (c) 2018-2019, Stanford University
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

#include "OpContext.h"

#include <mutex>

namespace Homa {
namespace Core {

/**
 * OpContextPool constructor.
 */
OpContextPool::OpContextPool(Transport* transport)
    : mutex()
    , transport(transport)
    , pool()
{}

/**
 * Construct a new OpContext object in the pool and return a pointer to it.
 *
 * @param isServerOp
 *      True if this context is for a ServerOp; false it is for a RemoteOp.
 * @sa OpContext()
 */
OpContext*
OpContextPool::construct(bool isServerOp)
{
    std::lock_guard<SpinLock> lock(mutex);
    return pool.construct(transport, isServerOp);
}

/**
 * Destory the given Message object previously allocated by this
 * MessagePool.
 */
void
OpContextPool::destroy(OpContext* opContext)
{
    std::lock_guard<SpinLock> lock(mutex);
    pool.destroy(opContext);
}

}  // namespace Core
}  // namespace Homa