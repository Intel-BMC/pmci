cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

project (pldmd CXX)

option (BUILD_STANDALONE "Use outside of YOCTO depedencies system" OFF)

set (BUILD_SHARED_LIBRARIES OFF)
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

set (
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
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
    -Wno-strict-aliasing \
    -Wno-cast-align \
    -Wformat=2 \
"
)

set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# Add header and sources here
set (SRC_FILES ${PROJECT_SOURCE_DIR}/src/pldmd.cpp
               ${PROJECT_SOURCE_DIR}/src/platform.cpp
               ${PROJECT_SOURCE_DIR}/src/sdbus-asio.cpp
)

set (HEADER_FILES ${PROJECT_SOURCE_DIR}/include/pldm.hpp
)

include_directories (${PROJECT_SOURCE_DIR}/include)

set (SERVICE_FILES
     ${PROJECT_SOURCE_DIR}/service_files/xyz.openbmc_project.pldmd.service)

add_executable(${PROJECT_NAME} ${SRC_FILES} ${HEADER_FILES})

target_link_libraries (${PROJECT_NAME} sdbusplus -lsystemd -lboost_system
                        -lpthread -lstdc++fs -lphosphor_dbus -lmctpw -lpldm_intel)

install (TARGETS ${PROJECT_NAME} DESTINATION bin)
install (FILES ${SERVICE_FILES} DESTINATION /lib/systemd/system/)
