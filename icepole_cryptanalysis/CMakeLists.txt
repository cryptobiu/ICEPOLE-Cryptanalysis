cmake_minimum_required(VERSION 2.8)

project(icepole_cryptanalysis)

cmake_policy(SET CMP0015 NEW)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++0x")

INCLUDE_DIRECTORIES(
	../icepole
)

link_directories(
	../icepole/icepole128av2/ref
)

set(SOURCE_FILES
	aes_prg.cpp
	icepole_cryptanalysis.cpp
	u03_attack.cpp
	u03_attack_validation.cpp
)

add_executable(icepole_cryptanalysis ${SOURCE_FILES})

target_link_libraries( icepole_cryptanalysis
	icepole_128AV2
	log4cpp
	event
	crypto
	pthread
)
