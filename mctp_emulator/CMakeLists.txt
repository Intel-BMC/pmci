cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

#Set project name here
project (mctp-emulator CXX)

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

#Add header and sources here
set (SRC_FILES ${PROJECT_SOURCE_DIR}/src/main.cpp ${PROJECT_SOURCE_DIR}/src/MCTPBinding.cpp
     ${PROJECT_SOURCE_DIR}/src/SMBusBinding.cpp)

set (HEADER_FILES ${PROJECT_SOURCE_DIR}/include/MCTPBinding.hpp
     ${PROJECT_SOURCE_DIR}/include/SMBusBinding.hpp)

include_directories (${PROJECT_SOURCE_DIR}/include)

set (
    SERVICE_FILES
    ${PROJECT_SOURCE_DIR}/service_files/xyz.openbmc_project.mctp-emulator.service
)


file(GLOB_RECURSE CONFIG_FILES "${PROJECT_SOURCE_DIR}/configurations/*.json")

add_executable (${PROJECT_NAME} ${SRC_FILES} ${HEADER_FILES})

target_link_libraries (${PROJECT_NAME} i2c sdbusplus -lsystemd
                       -lmctp_intel -lpthread -lstdc++fs -lphosphor_dbus -lboost_coroutine)

install (TARGETS ${PROJECT_NAME} DESTINATION bin)
install (FILES ${SERVICE_FILES} DESTINATION /lib/systemd/system/)
install (FILES ${CONFIG_FILES} DESTINATION /usr/share/mctp-emulator/)
