cmake_minimum_required(VERSION 3.10)
project(CyberThreatEngine VERSION 1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
include_directories(include)

file(GLOB_RECURSE ENGINE_SOURCES "src/*.c")

add_executable(ThreatEngine ${ENGINE_SOURCES})
