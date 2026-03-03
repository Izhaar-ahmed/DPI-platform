cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# Shared source files (parsers used by all targets)
# ============================================================================
set(SHARED_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# ============================================================================
# Target 1: packet_analyzer (preserve existing — simple packet viewer)
# Entry point: main.cpp only. Does NOT include rule_manager.cpp because
# dpi_mt.cpp has inline classes that would cause duplicate symbols.
# ============================================================================
add_executable(packet_analyzer
    src/main.cpp
    ${SHARED_SOURCES}
)

# ============================================================================
# Target 2: dpi_engine (THE REAL ENGINE)
# This is the production-quality multi-threaded DPI engine with full pipeline:
# Reader → Load Balancers → Fast Path Processors → Output Writer
# ============================================================================
add_executable(dpi_engine
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    ${SHARED_SOURCES}
)
target_link_libraries(dpi_engine PRIVATE pthread)

# ============================================================================
# Target 3: dpi_simple (standalone demo with inline pipeline)
# Entry point: main_working.cpp — self-contained minimal DPI demo
# ============================================================================
add_executable(dpi_simple
    src/main_working.cpp
    ${SHARED_SOURCES}
)

# ============================================================================
# AddressSanitizer support (cmake -DCMAKE_BUILD_TYPE=Asan)
# ============================================================================
if(CMAKE_BUILD_TYPE STREQUAL "Asan")
    message(STATUS "Building with AddressSanitizer enabled")
    set(SANITIZER_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
endif()

# ============================================================================
# Platform-specific settings
# ============================================================================
if(APPLE)
    # macOS: Apple Clang links pthreads by default
endif()
