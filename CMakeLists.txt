cmake_minimum_required(VERSION 3.20)
project(PackedSS)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -std=c++11 -maes -mpclmul -mbmi2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -O3 -std=c++11 -maes -mpclmul -mbmi2")
# thanks, ahegde 
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread)
if (Boost_FOUND) 
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
endif()
find_package(GMP REQUIRED)
find_package(NTL 11.0.0 REQUIRED)

INCLUDE_DIRECTORIES(${NTL_INCLUDE_DIR})

add_subdirectory(libscapi_utils)

add_executable(PackedSSTest PackedSS.hpp TemplateField.cpp UnitTestPackedSS.cpp) 
add_executable(MicroBench PackedSS.hpp TemplateField.cpp MicroBenchTest.cpp) 

TARGET_LINK_LIBRARIES(PackedSSTest OpenSSL::Crypto ${NTL_LIB} libscapi_utils gmp gmpxx
        ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} pthread crypto dl ssl z)
TARGET_LINK_LIBRARIES(MicroBench OpenSSL::Crypto ${NTL_LIB} libscapi_utils gmp gmpxx
        ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} pthread crypto dl ssl z)
