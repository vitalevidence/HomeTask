cmake_minimum_required(VERSION 3.20)

project(MyProject)

find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS})
include_directories(..)

add_executable(runTests CipherTests.cpp)
target_link_libraries(runTests ${GTEST_LIBRARIES} gtest_main crypto)

add_test(NAME MyTests COMMAND runTests)
