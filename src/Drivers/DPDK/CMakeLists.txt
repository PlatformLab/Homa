## lib DpdkDriver ##############################################################
add_library(DpdkDriver
    DpdkDriver.cc
    MacAddress.cc
)
add_library(Homa::DpdkDriver ALIAS DpdkDriver)
target_include_directories(DpdkDriver
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(DpdkDriver
    PUBLIC
        -Wl,--whole-archive Dpdk::Dpdk -Wl,--no-whole-archive
        Homa
        Threads::Threads
)
target_compile_options(DpdkDriver
    PRIVATE
        -mssse3
)
