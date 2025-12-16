cmake_minimum_required(VERSION 3.12)
project(ndt7_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

# Library
add_library(ndt7_c STATIC
    src/ndt7.c
)

target_include_directories(ndt7_c
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(ndt7_c
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

# Simple example client
add_executable(ndt7_c_client
    src/ndt7_client.c
)

target_link_libraries(ndt7_c_client
    PRIVATE ndt7_c
)


