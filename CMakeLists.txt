cmake_minimum_required (VERSION 3.0)

project (shs)

if (MSVC)
    add_compile_options(/W3 /WX)
else()
    add_compile_options(-W -Wall)
endif()

add_library(shslib sha256.c)
add_executable(tester tests.c)
target_link_libraries(tester shslib)
