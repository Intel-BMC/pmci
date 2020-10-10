cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

project (pldm_intel)

option (BUILD_STANDALONE "Use outside of YOCTO depedencies system" OFF)

set (BUILD_SHARED_LIBRARIES OFF)
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

set (
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -lstdc++fs \
    -Werror \
    -Wall \
    -Wextra \
    -Wshadow \
    -Wnon-virtual-dtor \
    -Wunused \
    -Woverloaded-virtual \
    -Wpedantic \
    -Wmisleading-indentation \
    -Wduplicated-cond \
    -Wduplicated-branches \
    -Wlogical-op \
    -Wnull-dereference \
    -Wdouble-promotion \
    -Wformat=2 \
"
)

set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# Add header and sources here
set (SRC_FILES ${PROJECT_SOURCE_DIR}/base.c
        ${PROJECT_SOURCE_DIR}/fru.c
        ${PROJECT_SOURCE_DIR}/firmware_update.c
        ${PROJECT_SOURCE_DIR}/pdr.c
        ${PROJECT_SOURCE_DIR}/platform.c
        ${PROJECT_SOURCE_DIR}/utils.c
)

set (HEADER_FILES ${PROJECT_SOURCE_DIR}/base.h
        ${PROJECT_SOURCE_DIR}/entity.h
        ${PROJECT_SOURCE_DIR}/fru.h
        ${PROJECT_SOURCE_DIR}/firmware_update.h
        ${PROJECT_SOURCE_DIR}/pdr.h
        ${PROJECT_SOURCE_DIR}/platform.h
        ${PROJECT_SOURCE_DIR}/pldm_types.h
        ${PROJECT_SOURCE_DIR}/state_set.h
        ${PROJECT_SOURCE_DIR}/utils.h
)

if (BUILD_STANDALONE)
    set (CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/libs/googletest/)

    configure_file (CMakeLists.txt.in 3rdparty/CMakeLists.txt)
    execute_process (COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
    execute_process (COMMAND ${CMAKE_COMMAND} --build .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)

    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/libs/googletest/include)
    link_directories (SYSTEM ${CMAKE_BINARY_DIR}/libs/googletest/lib)

endif ()

add_library (${PROJECT_NAME} ${SRC_FILES} ${HEADER_FILES})

install (TARGETS ${PROJECT_NAME} DESTINATION lib)
install (FILES ${HEADER_FILES} DESTINATION include)

include (CTest)

set (TEST_BASE tests/libpldm_base_test.cpp base.c)
set (TEST_FRU tests/libpldm_fru_test.cpp fru.c base.c utils.c)
set (TEST_FW_UPDATE tests/libpldm_fw_update_test.cpp firmware_update.c base.c utils.c)
set (TEST_PDR tests/libpldm_pdr_test.cpp pdr.c)
set (TEST_PLATFORM tests/libpldm_platform_test.cpp platform.c base.c)
set (TEST_UTILS tests/libpldm_utils_test.cpp utils.c)

enable_testing ()

find_package (GTest REQUIRED)

add_executable (libpldm_base_test ${TEST_BASE})
target_link_libraries(libpldm_base_test ${GTEST_LIBRARIES} -lpthread)
add_test (libpldm_base_test libpldm_base_test
          "--gtest_output=xml:libpldm_base_test.xml")

add_executable (libpldm_fru_test ${TEST_FRU})
target_link_libraries(libpldm_fru_test ${GTEST_LIBRARIES} -lpthread)
add_test (libpldm_fru_test libpldm_fru_test
          "--gtest_output=xml:libpldm_fru_test.xml")

add_executable (libpldm_fw_update_test ${TEST_FW_UPDATE})
target_link_libraries(libpldm_fw_update_test ${GTEST_LIBRARIES} -lpthread)
add_test (libpldm_fw_update_test libpldm_fw_update_test
          "--gtest_output=xml:libpldm_fw_update_test.xml")

add_executable (libpldm_pdr_test ${TEST_PDR})
target_link_libraries(libpldm_pdr_test ${GTEST_LIBRARIES} -lpthread)
add_test (libpldm_pdr_test libpldm_pdr_test
          "--gtest_output=xml:libpldm_pdr_test.xml")

add_executable (libpldm_platform_test ${TEST_PLATFORM})
target_link_libraries(libpldm_platform_test ${GTEST_LIBRARIES} -lpthread)
add_test (libpldm_platform_test libpldm_platform_test
          "--gtest_output=xml:libpldm_platform_test.xml")

add_executable (libpldm_utils_test ${TEST_UTILS})
target_link_libraries(libpldm_utils_test ${GTEST_LIBRARIES} -lpthread)
add_test (libpldm_utils_test libpldm_utils_test
          "--gtest_output=xml:libpldm_utils_test.xml")
