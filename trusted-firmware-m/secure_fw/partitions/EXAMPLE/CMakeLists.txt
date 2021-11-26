#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT TFM_PARTITION_EXAMPLE)
    if(TFM_PARTITION_PSA_PROXY)
    add_library(tfm_app_rot_partition_ps INTERFACE)

    target_include_directories(tfm_app_rot_partition_ps
        INTERFACE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    )
    endif()
    return()
endif()

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_app_rot_partition_example STATIC)

target_sources(tfm_app_rot_partition_example
    PRIVATE
        EXAMPLE.c
)
target_include_directories(tfm_app_rot_partition_example
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/EXAMPLE
)

# Set include directory
target_include_directories(tfm_app_rot_partition_example
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/EXAMPLE
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/EXAMPLE
)
# The generated sources
target_sources(tfm_app_rot_partition_example
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/EXAMPLE/auto_generated/intermedia_tfm_example.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/EXAMPLE/auto_generated/load_info_tfm_example.c
)


target_link_libraries(tfm_app_rot_partition_example
    PRIVATE
        tfm_secure_api
        psa_interface
        platform_s
        secure_fw
        tfm_sprt
)
target_sources(tfm_sprt
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tfm_example_api.c
)
# The veneers give warnings about not being properly declared so they get hidden
# to not overshadow _real_ warnings.
set_source_files_properties(tfm_example_api.c
    PROPERTIES
        COMPILE_FLAGS -Wno-implicit-function-declaration
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_example
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_EXAMPLE
)
