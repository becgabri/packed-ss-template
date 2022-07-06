cmake_minimum_required(VERSION 2.8)
project(PackedSS)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -std=c++11 -maes -mpclmul -mbmi2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -O3 -std=c++11 -maes -mpclmul -mbmi2")

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)
if (Boost_FOUND) 
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
endif()
find_library(NTLBUILD ntl PATHS $ENV{HOME}/ntl/lib)
if (NOT NTLBUILD) 
   message(FATAL ERROR "could not find NTL")
endif()


add_subdirectory(libscapi_utils)

add_executable(PackedSSTest PackedSS.hpp TemplateField.cpp UnitTestPackedSS.cpp) 
add_executable(MicroBench PackedSS.hpp TemplateField.cpp MicroBenchTest.cpp) 

TARGET_LINK_LIBRARIES(PackedSSTest OpenSSL::Crypto ${NTLBUILD} libscapi_utils gmp gmpxx
        libboost_system.a libboost_thread.a pthread crypto dl ssl z)
TARGET_LINK_LIBRARIES(MicroBench ${NTLBUILD} OpenSSL::Crypto libscapi_utils gmp gmpxx
        libboost_system.a libboost_thread.a pthread crypto dl ssl z)
