cmake_minimum_required(VERSION 3.14)
project(pulse_vpn LANGUAGES CXX)

set(BINARY_NAME "pulse_vpn")

cmake_policy(SET CMP0063 NEW)
set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE)

# Bundle Wintun driver loader and Win32 manifest
set(WINTUN_SOURCES
    "wintun_loader.h"
    "wintun_loader.cpp"
    "wintun.manifest"
)
