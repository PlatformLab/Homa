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
    src/Logger.cc
    src/MessageContext.cc
    src/Receiver.cc
    src/Rpc.cc
    src/RpcManager.cc
    src/RpcManagerImpl.cc
    src/Scheduler.cc
    src/Sender.cc
    src/ServerRpc.cc
    src/ThreadId.cc
    src/Transport.cc
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

## lib Drivers #################################################################

add_subdirectory(src/drivers)

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
