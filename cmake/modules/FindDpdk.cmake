# Copyright (c) 2018-2019, Stanford University
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
find_package(Threads REQUIRED)

find_library(DPDK_rte_pmd_mlx4_LIBRARY rte_pmd_mlx4)
find_library(DPDK_rte_pmd_mlx5_LIBRARY rte_pmd_mlx5)

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
    add_library(Dpdk::Dpdk INTERFACE IMPORTED)
    set_target_properties(Dpdk::Dpdk PROPERTIES
        INTERFACE_COMPILE_OPTIONS "-march=native"
        INTERFACE_INCLUDE_DIRECTORIES "${Dpdk_INCLUDE_DIR}"
    )
    target_link_libraries(Dpdk::Dpdk
        INTERFACE
            -Wl,--whole-archive
            ${Dpdk_LIBRARY}
            -Wl,--no-whole-archive
            ${Numa_LIBRARY}
            ${Dl_LIBRARY}
            Threads::Threads
    )
    if (DPDK_rte_pmd_mlx4_LIBRARY)
        target_link_libraries(Dpdk::Dpdk
            INTERFACE
                -lmnl
                -lmlx4
                -libverbs
        )
    endif()
    if (DPDK_rte_pmd_mlx5_LIBRARY)
        target_link_libraries(Dpdk::Dpdk
            INTERFACE
                -libverbs
                -lmlx5
        )
    endif()
endif()
