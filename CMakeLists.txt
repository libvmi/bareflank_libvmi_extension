cmake_minimum_required(VERSION 3.6)

vmm_extension(
		bareflank_libvmi_extension
		SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/exit_handler
)

