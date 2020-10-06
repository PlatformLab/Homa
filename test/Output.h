#pragma once

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace Output {

using Latency = std::chrono::duration<double>;

struct TimeDist {
    Latency min;   // Fastest time seen (seconds).
    Latency p50;   // Median time per operation (seconds).
    Latency p90;   // 90th percentile time/op (seconds).
    Latency p99;   // 99th percentile time/op (seconds).
    Latency p999;  // 99.9th percentile time/op (seconds).
};

std::string
format(const std::string& format, ...)
{
    va_list args;
    va_start(args, format);
    size_t len = std::vsnprintf(NULL, 0, format.c_str(), args);
    va_end(args);
    std::vector<char> vec(len + 1);
    va_start(args, format);
    std::vsnprintf(&vec[0], len + 1, format.c_str(), args);
    va_end(args);
    return &vec[0];
}

std::string
formatTime(Latency seconds)
{
    if (seconds < std::chrono::duration<double, std::micro>(1)) {
        return format(
            "%5.1f ns",
            std::chrono::duration<double, std::nano>(seconds).count());
    } else if (seconds < std::chrono::duration<double, std::milli>(1)) {
        return format(
            "%5.1f us",
            std::chrono::duration<double, std::micro>(seconds).count());
    } else if (seconds < std::chrono::duration<double>(1)) {
        return format(
            "%5.2f ms",
            std::chrono::duration<double, std::milli>(seconds).count());
    } else {
        return format("%5.2f s ", seconds.count());
    }
}

std::string
basicHeader()
{
    return "median       min       p90       p99      p999     description";
}

std::string
basic(std::vector<Latency>& times, const std::string description)
{
    int count = times.size();
    std::sort(times.begin(), times.end());

    TimeDist dist;

    dist.min = times[0];
    int index = count / 2;
    if (index < count) {
        dist.p50 = times.at(index);
    } else {
        dist.p50 = dist.min;
    }
    index = count - (count + 5) / 10;
    if (index < count) {
        dist.p90 = times.at(index);
    } else {
        dist.p90 = dist.p50;
    }
    index = count - (count + 50) / 100;
    if (index < count) {
        dist.p99 = times.at(index);
    } else {
        dist.p99 = dist.p90;
    }
    index = count - (count + 500) / 1000;
    if (index < count) {
        dist.p999 = times.at(index);
    } else {
        dist.p999 = dist.p99;
    }

    std::string output = "";
    output += format("%9s", formatTime(dist.p50).c_str());
    output += format(" %9s", formatTime(dist.min).c_str());
    output += format(" %9s", formatTime(dist.p90).c_str());
    output += format(" %9s", formatTime(dist.p99).c_str());
    output += format(" %9s", formatTime(dist.p999).c_str());
    output += "  ";
    output += description;
    return output;
}

}  // namespace Output
