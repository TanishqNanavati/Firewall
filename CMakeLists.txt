cmake_minimum_required(VERSION 3.10)
project(FIREWALL C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

include_directories(include)

add_executable(firewall
    main.c
    src/parser.c
    src/firewall_rules.c
    src/logger.c
)

# Link pcap library
target_link_libraries(firewall pcap)