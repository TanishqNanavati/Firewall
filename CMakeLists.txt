cmake_minimum_required(VERSION 3.10)
project(FIREWALL C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pthread")

add_compile_definitions(_DEFAULT_SOURCE)

include_directories(include)

add_executable(firewall
    main.c
    src/parser.c
    src/firewall_rules.c
    src/logger.c
    src/connection_tracker.c
)

target_link_libraries(firewall pcap pthread)