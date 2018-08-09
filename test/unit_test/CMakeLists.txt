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

add_executable(unit_test
    CodeLocationTest.cc
    ObjectPoolTest.cc
    TubTest.cc
    UtilTest.cc
)
target_link_libraries(unit_test gtest_main Homa)
# -fno-access-control allows access to private members for testing
target_compile_options(unit_test PRIVATE -fno-access-control)
# optionally add the tests that need std::thread.
if(Threads_FOUND)
    target_sources(unit_test PRIVATE
        ThreadIdTest.cc
    )
    target_link_libraries(unit_test Threads::Threads)
endif()
gtest_discover_tests(unit_test)
