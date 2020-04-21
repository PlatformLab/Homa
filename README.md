# Homa

An implementation of the Homa transport protocol as a C++ userspace library.

## What is the Homa transport protocol?

Homa is a new transport protocol for datacenter networks developed at the
[Stanford PlatformLab](https://platformlab.stanford.edu). Homa provides
exceptionally low latency, especially for workloads with a high volume of very
short messages, and it also supports large messages and high network
utilization. A complete description of Homa can be found in this 
[paper](https://arxiv.org/abs/1803.09615). A version of this was published in
ACM SIGCOMM 2018.

## What is this implementation?

This project aims to provide a implementation of the Homa transport protocol
that can be included by applications as a C++ library and can run completely in
userspace, bypassing the kernel for the best possible performance.

The implementation built in two layers:
  1. a "Packet Driver" which provides simple unreliable packet send/receive, and
  2. the Transport which implements the Homa protocol using packet send/receive.

This project provides a [DPDK](https://www.dpdk.org) based implementation of a
Driver which allows high performance packet processing for linux-based systems
with a range of NICs. The Transport is Driver agnostic so other environments can
be supported by building additional drivers.

## What is the current state of this implementation?

This implementation should be close to feature complete or at least runnable.
The interface, however, is still in flux and thus not stable to develop against.
Additionally, more testing needs to be done to ensure the implementation works
as expected.

## Quick Start

### Dependencies

Required:
  * CMake (>= 3.11)
  * DPDK (18.11)
  
Optional:
  * Doxygen
  * pthreads

### Download

```
git clone https://github.com/PlatformLab/Homa.git
```

### Build

From the `Homa` project directory:
```
cmake -E make_directory build
cmake -E chdir build cmake ..
cmake --build build
```

### Install (default install prefix)
```
sudo cmake --build build --target install
```
