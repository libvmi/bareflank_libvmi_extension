cmake_minimum_required(VERSION 3.6)
project(bareflank_libvmi_extension C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project()

add_vmm_executable(
    bareflank_libvmi_extension
    LIBRARIES eapis_hve
    SOURCES exit_handler.cpp
)
