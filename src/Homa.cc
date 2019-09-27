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

#include "Homa.h"
#include "Message.h"
#include "Transport.h"

namespace Homa {

RemoteOp::RemoteOp(Transport* transport)
    : request(transport->internal->alloc())
    , response(nullptr)
    , transport(transport)
    , opId()
    , state(State::NOT_STARTED)
{
    request->reserve(sizeof(Protocol::Message::Header));
}

RemoteOp::~RemoteOp()
{
    request->release();
    if (response != nullptr) {
        response->release();
    }
    SpinLock::Lock lock_transport(transport->members->mutex);
    transport->members->remoteOps.erase(opId);
}

void
RemoteOp::send(Driver::Address destination)
{
    state.store(State::IN_PROGRESS);
    uint32_t outboundTag = Protocol::Message::INITIAL_REQUEST_TAG;
    Driver::Address replyAddress = transport->driver->getLocalAddress();
    SpinLock::Lock lock_transport(transport->members->mutex);
    opId = Protocol::OpId(transport->members->transportId,
                          transport->members->nextOpSequenceNumber++);
    Protocol::Message::Header outboundHeader(opId, outboundTag);
    transport->driver->addressToWireFormat(replyAddress,
                                           &outboundHeader.replyAddress);
    request->prepend(&outboundHeader, sizeof(outboundHeader));
    transport->members->remoteOps.insert({opId, this});
    request->send(destination);
}

bool
RemoteOp::isReady()
{
    State copyOfState = state.load();
    switch (copyOfState) {
        case State::NOT_STARTED:
            return false;
            break;
        case State::IN_PROGRESS:
            if (request->getStatus() == OutMessage::Status::FAILED) {
                state.store(State::FAILED);
                return true;
            }
            return false;
            break;
        case State::COMPLETED:
            return true;
            break;
        case State::FAILED:
            return true;
            break;
        default:
            PANIC("Unknown RemoteOp state.");
    }
}

void
RemoteOp::wait()
{
    while (!isReady()) {
        transport->poll();
    }
}

ServerOp::ServerOp()
    : request(nullptr)
    , response(nullptr)
    , transport(nullptr)
    , state(State::NOT_STARTED)
    , detached(false)
    , opId()
    , requestTag(0)
    , replyAddress(0)
    , delegated(false)
{}

ServerOp::ServerOp(ServerOp&& other)
    : request(std::move(other.request))
    , response(std::move(other.response))
    , transport(std::move(other.transport))
    , state(other.state.load())
    , detached(other.detached.load())
    , opId(other.opId)
    , requestTag(other.requestTag)
    , replyAddress(other.replyAddress)
    , delegated(other.delegated)
{
    other.request = nullptr;
    other.response = nullptr;
    other.transport = nullptr;
    other.state.store(State::NOT_STARTED);
    other.detached.store(false);
    other.opId = Protocol::OpId();
    other.requestTag = 0;
    other.replyAddress = 0;
    other.delegated = false;
}

ServerOp::~ServerOp()
{
    if (transport != nullptr && !detached && state != State::NOT_STARTED) {
        // Automatically detach by default.
        detached.store(true);
        SpinLock::Lock lock_transport(transport->members->mutex);
        transport->members->detachedServerOps.emplace_back(std::move(*this));
    } else {
        if (request != nullptr) {
            request->release();
        }
        if (response != nullptr) {
            response->release();
        }
    }
}

ServerOp&
ServerOp::operator=(ServerOp&& other)
{
    request = std::move(other.request);
    response = std::move(other.response);
    transport = std::move(other.transport);
    state = other.state.load();
    detached = other.detached.load();
    opId = other.opId;
    requestTag = other.requestTag;
    replyAddress = other.replyAddress;
    delegated = other.delegated;

    other.request = nullptr;
    other.response = nullptr;
    other.transport = nullptr;
    other.state.store(State::NOT_STARTED);
    other.detached.store(false);
    other.opId = Protocol::OpId();
    other.requestTag = 0;
    other.replyAddress = 0;
    other.delegated = false;
    return *this;
}

ServerOp::operator bool() const
{
    if (request != nullptr) {
        return true;
    } else {
        return false;
    }
}

ServerOp::State
ServerOp::checkProgress()
{
    State copyOfState = state.load();
    OutMessage::Status outState = OutMessage::Status::NOT_STARTED;
    if (response != nullptr) {
        outState = response->getStatus();
    }
    if (copyOfState == State::NOT_STARTED) {
        // Nothing to do.
    } else if (copyOfState == State::IN_PROGRESS) {
        // ServerOp must have an inboundMessage to be IN_PROGRESS
        assert(request != nullptr);
        if (request->dropped()) {
            state.store(State::DROPPED);
        } else if ((outState == Homa::OutMessage::Status::COMPLETED) ||
                   (outState == Homa::OutMessage::Status::SENT && !delegated)) {
            state.store(State::COMPLETED);
            if (requestTag != Protocol::Message::INITIAL_REQUEST_TAG) {
                request->acknowledge();
            }
        } else if (outState == Homa::OutMessage::Status::FAILED) {
            state.store(State::FAILED);
            // Deregister the outbound message in case the application wants
            // to try again.
            response->cancel();
        }
    } else if (copyOfState == State::COMPLETED) {
        // Nothing to do.
    } else if (copyOfState == State::DROPPED) {
        // Nothing to do.
    } else if (copyOfState == State::FAILED) {
        if (detached) {
            assert(request != nullptr);
            // If detached, automatically return an ERROR back to the Sender now
            // that the Server has given up.
            request->fail();
        }
    } else {
        PANIC("Unknown ServerOp state.");
    }
    return state.load();
}

void
ServerOp::reply()
{
    if (request != nullptr) {
        Protocol::Message::Header header(
            opId, Protocol::Message::ULTIMATE_RESPONSE_TAG);
        transport->driver->addressToWireFormat(replyAddress,
                                               &header.replyAddress);
        response->prepend(&header, sizeof(header));
        response->send(replyAddress);
    } else {
        WARNING("Calling reply() on empty ServerOp; nothing will be sent.");
    }
}

void
ServerOp::delegate(Driver::Address destination)
{
    if (request != nullptr) {
        delegated = true;
        Protocol::Message::Header header(opId, requestTag + 1);
        transport->driver->addressToWireFormat(replyAddress,
                                               &header.replyAddress);
        response->prepend(&header, sizeof(header));
        response->send(destination);
    } else {
        WARNING("Calling delegate() on empty ServerOp; nothing will be sent.");
    }
}

Transport::Transport(Driver* driver, uint64_t transportId)
    : driver(driver)
    , internal(new Core::Transport(driver, transportId))
    , members(new TransportInternal(transportId))
{}

Transport::~Transport()
{
    members->mutex.lock();
    members->remoteOps.clear();
    for (auto it = members->pendingServerOps.begin();
         it != members->pendingServerOps.end();) {
        it = members->pendingServerOps.erase(it);
    }
    for (auto it = members->detachedServerOps.begin();
         it != members->detachedServerOps.end();) {
        it = members->detachedServerOps.erase(it);
    }
    members->detachedServerOps.clear();
}

ServerOp
Transport::receiveServerOp()
{
    ServerOp op;
    if (!members->pendingServerOps.empty()) {
        op = std::move(members->pendingServerOps.front());
        members->pendingServerOps.pop_front();

        op.response = internal->alloc();
        op.response->reserve(sizeof(Protocol::Message::Header));
        op.transport = this;
        op.state.store(ServerOp::State::IN_PROGRESS);
    }
    return op;
}

void
Transport::poll()
{
    internal->poll();
    // Process incoming messages
    for (InMessage* message = internal->receive(); message != nullptr;
         message = internal->receive()) {
        Protocol::Message::Header header;
        message->get(0, &header, sizeof(header));
        message->strip(sizeof(header));
        if (header.tag == Protocol::Message::ULTIMATE_RESPONSE_TAG) {
            // Incoming message is a response
            SpinLock::Lock lock_transport(members->mutex);
            auto it = members->remoteOps.find(header.opId);
            if (it != members->remoteOps.end()) {
                RemoteOp* op = it->second;
                op->response = message;
                op->state.store(RemoteOp::State::COMPLETED);
            } else {
                // There is no RemoteOp waiting for this message; Drop it.
                message->release();
            }
        } else {
            // Incoming message is a request.
            ServerOp op;
            op.request = message;
            op.opId = header.opId;
            op.requestTag = header.tag;
            op.replyAddress = driver->getAddress(&header.replyAddress);
            SpinLock::Lock lock_transport(members->mutex);
            members->pendingServerOps.emplace_back(std::move(op));
        }
    }
    // Check detached ServerOps
    {
        SpinLock::Lock lock_transport(members->mutex);
        auto it = members->detachedServerOps.begin();
        while (it != members->detachedServerOps.end()) {
            ServerOp::State state = it->checkProgress();
            assert(state != ServerOp::State::NOT_STARTED);
            if (state == ServerOp::State::IN_PROGRESS) {
                ++it;
            } else {
                it = members->detachedServerOps.erase(it);
            }
        }
    }
}

}  // namespace Homa
