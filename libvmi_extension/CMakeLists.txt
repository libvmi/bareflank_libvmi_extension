cmake_minimum_required(VERSION 3.6)

if(ENABLE_BUILD_VMM)
    add_subproject(bareflank_libvmi_extension vmm
        DEPENDS bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/exit_handler
    )
endif()