cmake_minimum_required (VERSION 3.0)

project (shs)

if (MSVC)
    add_compile_options(/W3 /WX)
else()
    add_compile_options(-g -W -Wall -std=c99)
endif()

add_library(shslib sha256.c sha1.c sha224.c sha512.c sha384.c sha512_224.c sha512_256.c)
add_executable(tester tests.c)
target_link_libraries(tester shslib)
