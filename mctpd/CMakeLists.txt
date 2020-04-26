cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

# Set project name here
project (mctpd CXX)

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
    -Wold-style-cast \
    -Wcast-align \
    -Wunused \
    -Woverloaded-virtual \
    -Wpedantic \
    -Wconversion \
    -Wmisleading-indentation \
    -Wduplicated-cond \
    -Wduplicated-branches \
    -Wlogical-op \
    -Wnull-dereference \
    -Wuseless-cast \
    -Wdouble-promotion \
    -Wformat=2 \
"
)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-strict-aliasing -Wno-cast-align")

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti -I ${STAGING_KERNEL_DIR}/include/uapi
     -I ${STAGING_KERNEL_DIR}/include")

set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# Add header and sources here
set (SRC_FILES ${PROJECT_SOURCE_DIR}/src/main.cpp ${PROJECT_SOURCE_DIR}/src/MCTPBinding.cpp
     ${PROJECT_SOURCE_DIR}/src/SMBusBinding.cpp)

set (HEADER_FILES ${PROJECT_SOURCE_DIR}/include/MCTPBinding.hpp
     ${PROJECT_SOURCE_DIR}/include/SMBusBinding.hpp)

include_directories (${PROJECT_SOURCE_DIR}/include)

set (
    SERVICE_FILES
    ${PROJECT_SOURCE_DIR}/service_files/xyz.openbmc_project.mctpd@.service
)

set (
    CONFIG_FILES
    ${PROJECT_SOURCE_DIR}/configurations/mctp_config.json
)

if (BUILD_STANDALONE)
    configure_file (CMakeLists.txt.in 3rdparty/CMakeLists.txt)
    execute_process (COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
    execute_process (COMMAND ${CMAKE_COMMAND} --build .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
    set (CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/prefix ${CMAKE_PREFIX_PATH})
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/prefix/include)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/sdbusplus-src)
    link_directories (${CMAKE_BINARY_DIR}/sdbusplus-src/.libs)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/phosphor-logging-src)
    link_directories (${CMAKE_BINARY_DIR}/phosphor-logging-src/.libs)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/libmctp-src)
    link_directories (${CMAKE_BINARY_DIR}/libmctp-src)
endif ()

find_package (Boost 1.71 REQUIRED)
include_directories (SYSTEM ${BOOST_SRC_DIR})

add_executable (${PROJECT_NAME} ${SRC_FILES} ${HEADER_FILES})
target_link_libraries (${PROJECT_NAME} sdbusplus -lsystemd -lboost_system
                        -lpthread -lstdc++fs)

if (BUILD_STANDALONE)
    target_link_libraries (${PROJECT_NAME}
                           ${CMAKE_BINARY_DIR}/libmctp/libmctp_intel.a)
else ()
    target_link_libraries (${PROJECT_NAME} -lmctp_intel i2c)
endif ()

if (${MCTPD_BUILD_UT})
include (CTest)

set (TEST_FILES tests/test-mctpd.cpp)

enable_testing ()

add_executable (test-mctpd ${TEST_FILES})
find_package (GTest REQUIRED)
target_link_libraries(test-mctpd ${GTEST_LIBRARIES} sdbusplus libmctp systemd -lpthread )

add_test (test-mctpd test-mctpd
          "--gtest_output=xml:test-mctpd.xml")
install (TARGETS test-mctpd DESTINATION bin)
endif (${MCTPD_BUILD_UT})

install (TARGETS ${PROJECT_NAME} DESTINATION bin)
install (FILES ${SERVICE_FILES} DESTINATION /lib/systemd/system/)
install (FILES ${CONFIG_FILES} DESTINATION /usr/share/mctp/)
