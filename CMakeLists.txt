cmake_minimum_required(VERSION 3.19)
project(wkMultiInstance)

set(CMAKE_CXX_STANDARD 20)

link_directories(lib)
include_directories(include)
configure_file(
        resource.rc.in
        resource.rc
)

add_library(wkMultiInstance SHARED src/dllmain.cpp src/handle.c ${CMAKE_CURRENT_BINARY_DIR}/resource.rc)
set_property(TARGET wkMultiInstance PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_link_libraries(wkMultiInstance libMinHook-x86-v141-mt)
