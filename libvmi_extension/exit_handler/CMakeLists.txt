cmake_minimum_required(VERSION 3.6)
project(bareflank_libvmi_extension C CXX)

init_project(bareflank_libvmi_extension BINARY)

target_sources(bareflank_libvmi_extension PRIVATE exit_handler.cpp)
target_link_libraries(bareflank_libvmi_extension PRIVATE vmm::bfvmm)

fini_project()