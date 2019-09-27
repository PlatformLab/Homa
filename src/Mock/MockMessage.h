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

#ifndef HOMA_MOCK_MESSAGE_H
#define HOMA_MOCK_MESSAGE_H

#include <gmock/gmock.h>

#include <Homa/Homa.h>

namespace Homa {
namespace Mock {

/**
 * MockInMessage is a gmock supported mock implementation of Homa::InMessage
 * that is used in unit testing.
 */
class MockInMessage : public Homa::InMessage {
  public:
    // Homa::Message methods
    MOCK_METHOD2(append, void(const void* source, uint32_t num));
    MOCK_CONST_METHOD3(get, uint32_t(uint32_t offset, void* destination,
                                     uint32_t num));
    MOCK_CONST_METHOD0(length, uint32_t());
    MOCK_METHOD2(prepend, void(const void* source, uint32_t num));
    MOCK_METHOD1(reserve, void(uint32_t num));
    MOCK_METHOD1(strip, void(uint32_t num));
    // Homa::InMessage methods
    MOCK_CONST_METHOD0(acknowledge, void());
    MOCK_CONST_METHOD0(fail, void());
    MOCK_CONST_METHOD0(dropped, bool());
    MOCK_METHOD0(release, void());
};

/**
 * MockOutMessage is a gmock supported mock implementation of Homa::OutMessage
 * that is used in unit testing.
 */
class MockOutMessage : public Homa::OutMessage {
  public:
    // Homa::Message methods
    MOCK_METHOD2(append, void(const void* source, uint32_t num));
    MOCK_CONST_METHOD3(get, uint32_t(uint32_t offset, void* destination,
                                     uint32_t num));
    MOCK_CONST_METHOD0(length, uint32_t());
    MOCK_METHOD2(prepend, void(const void* source, uint32_t num));
    MOCK_METHOD1(reserve, void(uint32_t num));
    MOCK_METHOD1(strip, void(uint32_t num));
    // Homa::OutMessage methods
    MOCK_METHOD1(send, void(Homa::Driver::Address destination));
    MOCK_METHOD0(cancel, void());
    MOCK_CONST_METHOD0(getStatus, Homa::OutMessage::Status());
    MOCK_METHOD0(release, void());
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MESSAGE_H
