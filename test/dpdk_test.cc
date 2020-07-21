#include <iostream>
#include <vector>

#include <Homa/Drivers/DPDK/DpdkDriver.h>
#include <Cycles.h>
#include <TimeTrace.h>
#include <docopt.h>

#include "Output.h"

static const char USAGE[] = R"(DPDK Driver Test.

    Usage:
        dpdk_test [options] <iface> (--server | <server_ip>)

    Options:
        -h --help           Show this screen.
        --version           Show version.
        --timetrace         Enable TimeTrace output [default: false].
)";

int
main(int argc, char* argv[])
{
    std::map<std::string, docopt::value> args =
            docopt::docopt(USAGE, {argv + 1, argv + argc},
                    true,                       // show help if requested
                    "DPDK Driver Test");        // version string

    std::string iface = args["<iface>"].asString();
    bool isServer = args["--server"].asBool();
    std::string server_ip_string;
    if (!isServer) {
        server_ip_string = args["<server_ip>"].asString();
    }

    Homa::Drivers::DPDK::DpdkDriver driver(iface.c_str());

    if (isServer) {
        std::cout << Homa::Util::ipToString(driver.getLocalAddress())
                  << std::endl;
        while (true) {
            Homa::Driver::Packet* incoming[10];
            uint32_t receivedPackets;
            do {
                receivedPackets = driver.receivePackets(10, incoming);
            } while (receivedPackets == 0);
            Homa::Driver::Packet* pong = driver.allocPacket();
            pong->length = 100;
            driver.sendPacket(pong, incoming[0]->sourceIp, 0);
            driver.releasePackets(incoming, receivedPackets);
            driver.releasePackets(&pong, 1);
        }
    } else {
        Homa::IpAddress server_ip =
                Homa::Util::stringToIp(server_ip_string.c_str());
        std::vector<Output::Latency> times;
        for (int i = 0; i < 100000; ++i) {
            uint64_t start = PerfUtils::Cycles::rdtsc();
            PerfUtils::TimeTrace::record(start, "START");
            Homa::Driver::Packet* ping = driver.allocPacket();
            PerfUtils::TimeTrace::record("allocPacket");
            ping->length = 100;
            PerfUtils::TimeTrace::record("set ping args");
            driver.sendPacket(ping, server_ip, 0);
            PerfUtils::TimeTrace::record("sendPacket");
            driver.releasePackets(&ping, 1);
            PerfUtils::TimeTrace::record("releasePacket");
            Homa::Driver::Packet* incoming[10];
            uint32_t receivedPackets;
            do {
                receivedPackets = driver.receivePackets(10, incoming);
                PerfUtils::TimeTrace::record("receivePackets");
            } while (receivedPackets == 0);
            driver.releasePackets(incoming, receivedPackets);
            PerfUtils::TimeTrace::record("releasePacket");
            uint64_t stop = PerfUtils::Cycles::rdtsc();
            times.emplace_back(PerfUtils::Cycles::toSeconds(stop - start));
        }
        if (args["--timetrace"].asBool()) {
            PerfUtils::TimeTrace::print();
        }
        std::cout << Output::basicHeader() << std::endl;
        std::cout << Output::basic(times, "DpdkDriver Ping-Pong") << std::endl;
    }

    return 0;
}