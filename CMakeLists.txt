cmake_minimum_required (VERSION 3.11)

project(Homa VERSION 0.1.0.0 LANGUAGES CXX)

################################################################################
## Dependency Configuration ####################################################
################################################################################

# Tell CMake where to find our custom/3rd-party "Find" modules
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

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
)
add_library(Homa::Homa ALIAS Homa)
target_include_directories(Homa
    PRIVATE
        ${PROJECT_BINARY_DIR}   # include so that we will find HomaConfig.h
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(Homa
)
target_compile_features(Homa
    PUBLIC
        cxx_std_11
)
set_target_properties(Homa PROPERTIES
    VERSION ${Homa_VERSION}
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
    src/HomaTest.cc
)
target_link_libraries(unitTest gtest_main Homa)
gtest_discover_tests(unitTest)

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
