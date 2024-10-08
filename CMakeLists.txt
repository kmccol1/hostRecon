cmake_minimum_required(VERSION 3.10)
project(hostRecon)

set(CMAKE_CXX_STANDARD 11)

# Set the CMAKE_PREFIX_PATH if you need to specify where to find libraries
set(CMAKE_PREFIX_PATH "/usr/local")

# Use pkg-config to find the pcap library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Include directories
include_directories(${PCAP_INCLUDE_DIRS} include)  # Include the 'include' directory for doctest

# Add the library that contains the implementation
add_library(hostReconLib src/networkScanner.cpp)

# Add executable for the main application
add_executable(hostRecon src/main.cpp) # Assuming you have a separate main.cpp file
target_link_libraries(hostRecon hostReconLib ${PCAP_LIBRARIES})

# Add test executable
add_executable(test_network_scanner tests/test_network_scanner.cpp)
target_include_directories(test_network_scanner PRIVATE include)  # Specify where to find doctest.h
target_link_libraries(test_network_scanner hostReconLib ${PCAP_LIBRARIES})  # Link to the library

# Add testing capabilities
enable_testing()
add_test(NAME test_network_scanner COMMAND test_network_scanner)
