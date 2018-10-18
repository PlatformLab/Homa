cmake_minimum_required (VERSION 3.11)

project(Homa VERSION 0.1.0.0 LANGUAGES CXX)

################################################################################
## Dependency Configuration ####################################################
################################################################################

# Tell CMake where to find our custom/3rd-party "Find" modules
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

# Thread library
find_package(Threads)

# Doxygen documentation generation tool (http://www.doxygen.org)
find_package(Doxygen OPTIONAL_COMPONENTS dot mscgen dia)

find_package(Dpdk REQUIRED)

################################################################################
## Source Configuration ########################################################
################################################################################
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/src/HomaConfig.h.in"
    "${PROJECT_BINARY_DIR}/HomaConfig.h"
)

################################################################################
## Target Defintions ###########################################################
################################################################################ 

## lib Homa ####################################################################
add_library(Homa
    src/CodeLocation.cc
    src/Debug.cc
    src/Homa.cc
    src/MessageContext.cc
    src/Receiver.cc
    src/Rpc.cc
    src/RpcManager.cc
    src/RpcManagerImpl.cc
    src/Scheduler.cc
    src/Sender.cc
    src/ServerRpc.cc
    src/StringUtil.cc
    src/ThreadId.cc
    src/TransportImpl.cc
    src/Util.cc
)
add_library(Homa::Homa ALIAS Homa)
target_include_directories(Homa
    PRIVATE
        ${PROJECT_BINARY_DIR}   # include so that we will find HomaConfig.h
        # ${CMAKE_CURRENT_SOURCE_DIR}/src     # for internal implementation
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(Homa
    PUBLIC
        cxx_std_11
)
set_target_properties(Homa PROPERTIES
    VERSION ${Homa_VERSION}
)

################################################################################
## Drivers #####################################################################
################################################################################

## lib DpdkDriver ##############################################################
add_library(DpdkDriver
    src/Drivers/DPDK/DpdkDriver.cc
    src/Drivers/DPDK/DpdkDriverImpl.cc
    src/Drivers/DPDK/MacAddress.cc
)
add_library(Homa::DpdkDriver ALIAS DpdkDriver)
target_include_directories(DpdkDriver
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(DpdkDriver
    PRIVATE
        -Wl,--whole-archive Dpdk::Dpdk -Wl,--no-whole-archive
        Threads::Threads
    PUBLIC
        Homa
)
target_compile_options(DpdkDriver
    PRIVATE
        -mssse3
)

################################################################################
## Tests #######################################################################
################################################################################

add_subdirectory(test)

################################################################################
## Generate Docs ###############################################################
################################################################################

if(DOXYGEN_FOUND)
    doxygen_add_docs(docs
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
endif()

################################################################################
## Install & Export ############################################################
################################################################################

install(TARGETS Homa DpdkDriver EXPORT HomaTargets 
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(
    DIRECTORY
        include/Homa
    DESTINATION
        include
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/Homa/HomaConfigVersion.cmake"
    VERSION ${Homa_VERSION}
    COMPATIBILITY SameMinorVersion
)

export(EXPORT HomaTargets
    NAMESPACE Homa::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/Homa/HomaTargets.cmake"
)

install(EXPORT HomaTargets
    DESTINATION lib/cmake/Homa
    NAMESPACE Homa::
    FILE HomaTargets.cmake
)

configure_file(cmake/HomaConfig.cmake
    "${CMAKE_CURRENT_BINARY_DIR}/Homa/HomaConfig.cmake"
    COPYONLY
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/Homa/HomaConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/Homa/HomaConfigVersion.cmake"
        DESTINATION lib/cmake/Homa
)

################################################################################
##  UNIT TESTS  ################################################################
################################################################################

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        ba96d0b1161f540656efdaed035b3c062b60e006
)

FetchContent_GetProperties(googletest)
if(NOT googletest_POPULATED)
    FetchContent_Populate(googletest)
    add_subdirectory(
        ${googletest_SOURCE_DIR}
        ${googletest_BINARY_DIR}
        EXCLUDE_FROM_ALL
    )
endif()

include(GoogleTest)

enable_testing()

add_executable(unit_test
    src/CodeLocationTest.cc
    src/DebugTest.cc
    src/HomaTest.cc
    src/MessageContextTest.cc
    src/ObjectPoolTest.cc
    src/ReceiverTest.cc
    src/RpcTest.cc
    src/SchedulerTest.cc
    src/SenderTest.cc
    src/SpinLockTest.cc
    src/STLUtilTest.cc
    src/StringUtilTest.cc
    src/ThreadIdTest.cc
    src/TransportImplTest.cc
    src/TubTest.cc
    src/UtilTest.cc
)
target_link_libraries(unit_test gmock_main Homa)
# -fno-access-control allows access to private members for testing
target_compile_options(unit_test PRIVATE -fno-access-control)
gtest_discover_tests(unit_test)
