cmake_minimum_required(VERSION 3.15)
project(dio C)

set(CMAKE_C_STANDARD 11)

add_executable(dio dio.c dio.h lib/const.h lib/block.c lib/block.h lib/utility.c lib/utility.h lib/md5.c lib/md5.h)