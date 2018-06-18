cmake_minimum_required(VERSION 2.8)
project(icepole_cryptanalysis)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++0x")

set(SOURCE_FILES
	icepole_cryptanalysis.cpp
)

add_executable(icepole_cryptanalysis ${SOURCE_FILES})

target_link_libraries( icepole_cryptanalysis
	log4cpp
	event
	pthread
)
