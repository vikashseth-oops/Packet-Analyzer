cmake_minimum_required(VERSION 3.14)
project(PacketAnalyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

# Main DPI Engine executable
add_executable(dpi_engine
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/types.cpp
)

# Multi-threaded alternative CLI executable
add_executable(dpi_mt
    src/dpi_mt.cpp
    src/sni_extractor.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/types.cpp
)

# Simple standalone packet analyzer executable
add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/types.cpp
)