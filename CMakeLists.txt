cmake_minimum_required(VERSION 3.22)

project(RSS-Reader)

find_package(OpenSSL REQUIRED)

#link_directories(OPENSSL_INCLUDE_DIR)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(RSS-Reader main.cpp)

target_link_libraries(RSS-Reader ${OPENSSL_LIBRARIES})

#TODO: Find a way to install openssl
