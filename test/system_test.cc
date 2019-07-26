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

#include <atomic>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

#include "docopt.h"

#include <Homa/Debug.h>
#include <Homa/Homa.h>
#include "Drivers/Fake/FakeDriver.h"

#include "StringUtil.h"

static const char USAGE[] = R"(Homa System Test.

    Usage:
        system_test <count> [-v | -vv | -vvv | -vvvv] [options]
        system_test (-h | --help)
        system_test --version

    Options:
        -h --help       Show this screen.
        --version       Show version.
        -v --verbose    Show verbose output.
        --hops=<n>      Number of hops an op should make [default: 1].
        --servers=<n>   Number of virtual servers [default: 1].
        --size=<n>      Number of bytes to send as a payload [default: 10].
        --lossRate=<f>  Rate at which packets are lost [default: 0.0].
)";

bool _PRINT_CLIENT_ = false;
bool _PRINT_SERVER_ = false;

struct MessageHeader {
    uint64_t id;
    uint64_t hops;
    uint64_t length;
} __attribute__((packed));

struct Node {
    explicit Node(uint64_t id)
        : id(id)
        , driver()
        , transport(&driver, id)
        , thread()
        , run(false)
    {}

    const uint64_t id;
    Homa::Drivers::Fake::FakeDriver driver;
    Homa::Transport transport;
    std::thread thread;
    std::atomic<bool> run;
};

void
serverMain(Node* server, std::vector<std::string> addresses)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, addresses.size() - 1);

    while (true) {
        if (server->run.load() == false) {
            break;
        }
        Homa::ServerOp op = server->transport.receiveServerOp();
        if (op) {
            MessageHeader header;
            op.request->get(0, &header, sizeof(MessageHeader));

            char buf[header.length];
            op.request->get(sizeof(MessageHeader), &buf, header.length);

            if (_PRINT_SERVER_) {
                std::cout << "  -> Server " << server->id
                          << " (opId: " << header.id << " hops:" << header.hops
                          << ")" << std::endl;
            }

            if (_PRINT_SERVER_) {
                std::cout << "  <- Server " << server->id
                          << " (opId: " << header.id << " hops:" << header.hops
                          << ")" << std::endl;
            }

            header.hops--;
            op.response->append(&header, sizeof(MessageHeader));
            op.response->append(buf, header.length);
            if (header.hops == 0) {
                op.reply();
            } else {
                std::string nextAddress = addresses[dis(gen)];
                Homa::Driver::Address nextServerAddress =
                    server->driver.getAddress(&nextAddress);
                op.delegate(nextServerAddress);
            }
        }
        server->transport.poll();
    }
}

/**
 * @return
 *      Number of Op that failed.
 */
int
clientMain(int count, int hops, int size, std::vector<std::string> addresses)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> randAddr(0, addresses.size() - 1);
    std::uniform_int_distribution<char> randData(0);

    uint64_t nextId = 0;
    int numFailed = 0;

    Node client(1);
    for (int i = 0; i < count; ++i) {
        uint64_t id = nextId++;
        char payload[size];
        for (int i = 0; i < size; ++i) {
            payload[i] = randData(gen);
        }

        std::string destAddress = addresses[randAddr(gen)];

        Homa::RemoteOp op(&client.transport);
        {
            MessageHeader header;
            header.id = id;
            header.hops = hops;
            header.length = size;
            op.request->append(&header, sizeof(MessageHeader));
            op.request->append(payload, size);
            if (_PRINT_CLIENT_) {
                std::cout << "Client -> (opId: " << header.id
                          << " hops:" << header.hops << ")" << std::endl;
            }
        }

        op.send(client.driver.getAddress(&destAddress));
        op.wait();

        {
            if (op.response == nullptr) {
                numFailed++;
                continue;
            }
            MessageHeader header;
            char buf[size];
            op.response->get(0, &header, sizeof(MessageHeader));
            op.response->get(sizeof(MessageHeader), &buf, header.length);
            if (header.id != id || header.hops != 0 || header.length != size ||
                memcmp(payload, buf, size) != 0) {
                numFailed++;
            }
            if (_PRINT_CLIENT_) {
                std::cout << "Client <- (opId: " << header.id
                          << " hops:" << header.hops << ")" << std::endl;
            }
        }
    }
    return numFailed;
}

int
main(int argc, char* argv[])
{
    std::map<std::string, docopt::value> args =
        docopt::docopt(USAGE, {argv + 1, argv + argc},
                       true,                 // show help if requested
                       "Homa System Test");  // version string

    // Read in args.
    int numTests = args["<count>"].asLong();
    int numHops = args["--hops"].asLong();
    int numServers = args["--servers"].asLong();
    int numBytes = args["--size"].asLong();
    int verboseLevel = args["--verbose"].asLong();
    double packetLossRate = atof(args["--lossRate"].asString().c_str());

    // level of verboseness
    bool printSummary = false;
    if (verboseLevel > 0) {
        printSummary = true;
        Homa::Debug::setLogPolicy(Homa::Debug::logPolicyFromString("ERROR"));
    }
    if (verboseLevel > 1) {
        Homa::Debug::setLogPolicy(Homa::Debug::logPolicyFromString("WARNING"));
    }
    if (verboseLevel > 2) {
        _PRINT_CLIENT_ = true;
        Homa::Debug::setLogPolicy(Homa::Debug::logPolicyFromString("NOTICE"));
    }
    if (verboseLevel > 3) {
        _PRINT_SERVER_ = true;
        Homa::Debug::setLogPolicy(Homa::Debug::logPolicyFromString("VERBOSE"));
    }

    Homa::Drivers::Fake::FakeNetworkConfig::setPacketLossRate(packetLossRate);

    uint64_t nextServerId = 101;
    std::vector<std::string> addresses;
    std::vector<Node*> servers;
    for (int i = 0; i < numServers; ++i) {
        Node* server = new Node(nextServerId++);
        addresses.emplace_back(std::string(
            server->driver.addressToString(server->driver.getLocalAddress())));
        servers.push_back(server);
    }

    for (auto it = servers.begin(); it != servers.end(); ++it) {
        Node* server = *it;
        server->run = true;
        server->thread = std::move(std::thread(&serverMain, server, addresses));
    }

    int numFails = clientMain(numTests, numHops, numBytes, addresses);

    for (auto it = servers.begin(); it != servers.end(); ++it) {
        Node* server = *it;
        server->run = false;
        server->thread.join();
        delete server;
    }

    if (printSummary) {
        std::cout << numTests << " Ops tested (hops: " << numHops
                  << "): " << numTests - numFails << " completed, " << numFails
                  << " failed" << std::endl;
    }

    return numFails;
}
