cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(mctpwplus CXX)

option(YOCTO_DEPENDENCIES "Use YOCTO depedencies system" OFF)
option(BUILD_EXAMPLES "Build example applications inside examples directory"
       OFF)

set(BUILD_SHARED_LIBRARIES ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS
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
    -Wnull-dereference \
    -Wdouble-promotion \
    -Wno-strict-aliasing \
    -Wno-cast-align \
    -Wformat=2 \
")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} \
        -Wuseless-cast \
        -Wduplicated-cond \
        -Wduplicated-branches \
        -Wlogical-op \
    ")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

if(NOT ${YOCTO_DEPENDENCIES})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-conversion \ ")
  set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/libs/googletest/
                        ${CMAKE_BINARY_DIR}/libs/boost/ ${CMAKE_PREFIX_PATH})

  configure_file(CMakeLists.txt.in 3rdparty/CMakeLists.txt)
  execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
  execute_process(COMMAND ${CMAKE_COMMAND} --build .
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)

  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/sdbusplus/include)
  link_directories(${CMAKE_BINARY_DIR}/libs/sdbusplus/lib)
  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/src/phosphor-logging)
  link_directories(${CMAKE_BINARY_DIR}/src/phosphor-logging/.libs)
  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/boost/include)
  link_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/boost/lib)
  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/CLIUtils/include)
endif()

find_package(Boost 1.71 REQUIRED)
include_directories(SYSTEM ${BOOST_SRC_DIR})

include_directories(${PROJECT_SOURCE_DIR})

add_library(mctpwplus SHARED mctp_wrapper.cpp dbus_cb.cpp service_monitor.cpp)

if(${BUILD_EXAMPLES})
  add_executable(wrapper_object examples/wrapper_object.cpp)
  add_dependencies(wrapper_object ${PROJECT_NAME})
  target_link_libraries(wrapper_object mctpwplus sdbusplus -lsystemd
                        -lboost_coroutine -lpthread)

  add_executable(scan_endpoints examples/scan_endpoints.cpp)
  add_dependencies(scan_endpoints ${PROJECT_NAME})
  target_link_libraries(scan_endpoints mctpwplus sdbusplus -lboost_coroutine
                        -lpthread)

  add_executable(send_receive examples/send_receive.cpp)
  add_dependencies(send_receive ${PROJECT_NAME})
  target_link_libraries(send_receive mctpwplus sdbusplus -lboost_coroutine
                        -lpthread)

  add_executable(receive_callback examples/receive_callback.cpp)
  add_dependencies(receive_callback ${PROJECT_NAME})
  target_link_libraries(receive_callback mctpwplus sdbusplus -lboost_coroutine
                        -lpthread)

  add_executable(mctp_device_manager examples/device_manager.cpp)
  add_dependencies(mctp_device_manager ${PROJECT_NAME})
  target_link_libraries(mctp_device_manager mctpwplus sdbusplus -lboost_coroutine
                        -lpthread)
endif()

set_target_properties(mctpwplus PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(mctpwplus PROPERTIES PUBLIC_HEADER mctp_wrapper.hpp)

install(
  TARGETS ${PROJECT_NAME} mctpwplus
  LIBRARY DESTINATION /usr/lib
  PUBLIC_HEADER DESTINATION /usr/include)
