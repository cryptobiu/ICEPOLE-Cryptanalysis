cmake_minimum_required(VERSION 2.8)

project(icepole_128AV2)

set(SOURCE_FILES
	encrypt.c
	icepole.c
)

add_library(icepole_128AV2 STATIC ${SOURCE_FILES})

