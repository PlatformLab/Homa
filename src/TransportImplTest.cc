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

#include <Homa/Debug.h>
#include <gtest/gtest.h>

#include "Mock/MockDriver.h"
#include "Mock/MockReceiver.h"
#include "Mock/MockSender.h"
#include "Protocol.h"
#include "TransportImpl.h"
#include "Tub.h"

namespace Homa {
namespace Core {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArrayArgument;

class TransportImplTest : public ::testing::Test {
  public:
    TransportImplTest()
        : mockDriver(allocMockDriver())
        , mockSender(new NiceMock<Homa::Mock::MockSender>(22, mockDriver, 0, 0))
        , mockReceiver(new NiceMock<Homa::Mock::MockReceiver>(mockDriver, 0, 0))
        , transport(mockDriver, nullptr, mockSender, mockReceiver, 22)
    {
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~TransportImplTest()
    {
        delete mockDriver;
        PerfUtils::Cycles::mockTscValue = 0;
    }

    NiceMock<Homa::Mock::MockDriver>* allocMockDriver()
    {
        auto driver = new NiceMock<Homa::Mock::MockDriver>();
        ON_CALL(*driver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(*driver, getMaxPayloadSize).WillByDefault(Return(1024));
        return driver;
    }

    NiceMock<Homa::Mock::MockDriver>* mockDriver;
    NiceMock<Homa::Mock::MockSender>* mockSender;
    NiceMock<Homa::Mock::MockReceiver>* mockReceiver;
    TransportImpl transport;
};

TEST_F(TransportImplTest, processPacket)
{
    // tested sufficiently in PollModeTransportImpl tests
}

}  // namespace
}  // namespace Core
}  // namespace Homa
