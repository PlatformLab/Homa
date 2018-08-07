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
    src/Homa.cc
    src/Scheduler.cc
    src/Sender.cc
    src/CodeLocation.cc
    src/Logger.cc
    src/MacAddress.cc
    src/MessageContext.cc
    src/Receiver.cc
    src/ThreadId.cc
    src/Util.cc
)
add_library(Homa::Homa ALIAS Homa)
target_include_directories(Homa
    PRIVATE
        ${PROJECT_BINARY_DIR}   # include so that we will find HomaConfig.h
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(Homa
    PUBLIC
        cxx_std_11
)
set_target_properties(Homa PROPERTIES
    VERSION ${Homa_VERSION}
)

## lib DpdkDriver ##############################################################
add_library(DpdkDriver
    src/DpdkDriver.cc
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

################################################################################
## Tests #######################################################################
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

add_executable(unitTest
    src/CodeLocationTest.cc
    src/MacAddressTest.cc
    src/ObjectPoolTest.cc
    src/TubTest.cc
    src/UtilTest.cc
)
target_link_libraries(unitTest gtest_main Homa)
# -fno-access-control allows access to private members for testing
target_compile_options(unitTest PRIVATE -fno-access-control)
# optionally add the tests that need std::thread.
if(Threads_FOUND)
    target_sources(unitTest PRIVATE
        src/ThreadIdTest.cc
    )
    target_link_libraries(unitTest Threads::Threads)
endif()
gtest_discover_tests(unitTest)

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

install(TARGETS Homa EXPORT HomaTargets 
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(
    FILES
        src/Homa.h
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
    FILE "${CMAKE_CURRENT_BINARY_DIR}/Homa/HomaTargets.cmake"
)

install(EXPORT HomaTargets
    FILE HomaTargets.cmake
    DESTINATION lib/cmake/Homa
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
