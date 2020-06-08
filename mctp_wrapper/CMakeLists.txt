cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

# Set project name here
project (mctpw CXX)

option (BUILD_STANDALONE "Use outside of YOCTO depedencies system" OFF)

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

find_package (Boost 1.71 REQUIRED)
include_directories (SYSTEM ${BOOST_SRC_DIR})

include_directories (${PROJECT_SOURCE_DIR})

add_library (${PROJECT_NAME} SHARED mctpw.cpp)
target_link_libraries (${PROJECT_NAME} sdbusplus -lsystemd
                        -lpthread -lstdc++fs -lphosphor_dbus -lmctp_intel)

add_executable(register examples/register.cpp mctpw.h)
add_dependencies(register ${PROJECT_NAME})
target_link_libraries(register mctpw)

install (TARGETS ${PROJECT_NAME} DESTINATION /usr/local/lib)

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



