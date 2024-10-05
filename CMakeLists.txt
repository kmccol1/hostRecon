cmake_minimum_required(VERSION 3.10)
project(hostRecon)

set(CMAKE_CXX_STANDARD 11)

# Set the CMAKE_PREFIX_PATH if you need to specify where to find libraries
set(CMAKE_PREFIX_PATH "/usr/local")

# Use pkg-config to find the pcap library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})

add_executable(hostRecon src/networkScanner.cpp)
target_link_libraries(hostRecon ${PCAP_LIBRARIES})

# Add test executable
add_executable(test_network_scanner tests/test_network_scanner.cpp)
target_link_libraries(test_network_scanner ${PCAP_LIBRARIES} doctest)
