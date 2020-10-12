cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

# Set project name here
project (mctpw CXX)

option (YOCTO_DEPENDENCIES "Use YOCTO depedencies system" OFF)

set (BUILD_SHARED_LIBRARIES ON)
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

if (NOT YOCTO_DEPENDENCIES)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-conversion \ ")
    set (CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/libs/googletest/
         ${CMAKE_BINARY_DIR}/libs/boost/ ${CMAKE_PREFIX_PATH})

    configure_file (CMakeLists.txt.in 3rdparty/CMakeLists.txt)
    execute_process (COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
    execute_process (COMMAND ${CMAKE_COMMAND} --build .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)

    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/libs/sdbusplus/include)
    link_directories (${CMAKE_BINARY_DIR}/libs/sdbusplus/lib)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/src/phosphor-logging)
    link_directories (${CMAKE_BINARY_DIR}/src/phosphor-logging/.libs)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/libs/libmctp/include)
    link_directories (${CMAKE_BINARY_DIR}/libs/libmctp/lib)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/libs/boost/include)
    link_directories (SYSTEM ${CMAKE_BINARY_DIR}/libs/boost/lib)
endif ()

find_package (Boost 1.71 REQUIRED)
include_directories (SYSTEM ${BOOST_SRC_DIR})

include_directories (${PROJECT_SOURCE_DIR})

add_library (${PROJECT_NAME} SHARED mctpw.cpp)
target_link_libraries (${PROJECT_NAME} sdbusplus -lsystemd -lboost_coroutine
                        -lpthread -lstdc++fs -lmctp_intel)

add_executable(register examples/register.cpp mctpw.h)
add_dependencies(register ${PROJECT_NAME})
target_link_libraries(register mctpw)

add_executable(sendreceive examples/sendreceive.cpp mctpw.h)
add_dependencies(sendreceive ${PROJECT_NAME})
target_link_libraries(sendreceive mctpw)

SET_TARGET_PROPERTIES (${PROJECT_NAME} PROPERTIES VERSION 1.0.0 SOVERSION 1 )
SET_TARGET_PROPERTIES (${PROJECT_NAME} PROPERTIES PUBLIC_HEADER mctpw.h)

INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION /usr/lib
        PUBLIC_HEADER DESTINATION /usr/include
)

find_package(Doxygen
             OPTIONAL_COMPONENTS dot mscgen dia)
if (${DOXYGEN_FOUND})
set(DOXYGEN_GENERATE_HTML YES)
set(DOXYGEN_GENERATE_MAN YES)
set(OUTPUT_DIRECTORY ${PROJECT_NAME}/doc)

doxygen_add_docs(
    mctpw
    ${PROJECT_SOURCE_DIR}
)
endif (${DOXYGEN_FOUND})
