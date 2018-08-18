CMAKE_MINIMUM_REQUIRED(VERSION 3.0)
PROJECT(uvsocks5 C)

SET(CMAKE_C_STANDARD 99)

OPTION(ENABLE_PROGRAM "Build socks5 program." OFF)


# LIBUV DIR
SET(LIBUV_DIR ${CMAKE_SOURCE_DIR}/libuv)

SET(SOCKS5LIBUV_ADDTION_HDR
        ${LIBUV_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
        )

INCLUDE_DIRECTORIES(${SOCKS5LIBUV_ADDTION_HDR})

# ADD LIBUV PROJECT
ADD_SUBDIRECTORY(${LIBUV_DIR})
ADD_SUBDIRECTORY(program)

IF( ENABLE_PROGRAM )
    ADD_SUBDIRECTORY(program)
ENDIF()

SET(SOCKS5LIBUV_SRCS
        src/s5.c
        src/server.c
        src/util.c
        src/base.c
        src/list.c
        src/dnsc.c
        src/flow.c
)

ADD_LIBRARY(uvsocks5 STATIC ${SOCKS5LIBUV_SRCS})
TARGET_LINK_LIBRARIES(uvsocks5 uv_a)
