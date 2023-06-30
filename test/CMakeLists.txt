cmake_minimum_required (VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/MESA/include)
include_directories(/usr/include/)
include_directories(${PROJECT_SOURCE_DIR}/src/)

link_directories(/opt/MESA/lib)
link_directories("${CMAKE_BINARY_DIR}")

add_executable(gtest_mesa gtest_mesa_sts.cpp)
target_link_libraries(gtest_mesa gtest-static pcap pthread mesa_sts)

file(COPY pcap DESTINATION ./)
