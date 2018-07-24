# Copyright (c) 2018, Stanford University
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# FindDpdk
# --------
#
# Finds the DPDK library (dpdk.org)
#
# This will define the following variables::
#
#   Dpdk_FOUND      - True if the system has the DPDK library
#
# and the following imported targets::
#
#   Dpdk::Dpdk      - The DPDK library
#
# Note: This find module is only intended to work with a DPDK library that is
#       installed in under a common install prefix.

find_path(Dpdk_INCLUDE_DIR rte_config.h
    PATH_SUFFIXES "dpdk"
)
find_library(Dpdk_LIBRARY dpdk)
find_library(Numa_LIBRARY numa)
find_library(Dl_LIBRARY dl)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Dpdk
    FOUND_VAR Dpdk_FOUND
    REQUIRED_VARS
        Dpdk_INCLUDE_DIR
        Dpdk_LIBRARY
        Numa_LIBRARY
        Dl_LIBRARY
)

if(Dpdk_FOUND AND NOT TARGET Dpdk::Dpdk)
    add_library(Dpdk::Dpdk STATIC IMPORTED)
    set_target_properties(Dpdk::Dpdk PROPERTIES
        IMPORTED_LOCATION "${Dpdk_LIBRARY}"
        INTERFACE_COMPILE_OPTIONS ""
        INTERFACE_INCLUDE_DIRECTORIES "${Dpdk_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${Numa_LIBRARY};${Dl_LIBRARY}"
    )
endif()
