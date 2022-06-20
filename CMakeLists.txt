cmake_minimum_required(VERSION 2.8)
project(PackedSS)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -std=c++11 -maes -mpclmul -mbmi2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -O3 -std=c++11 -maes -mpclmul -mbmi2")

INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/install/include/OTExtensionBristol)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib )

add_executable(PackedSSTest PackedSS.hpp TemplateField.cpp UnitTestPackedSS.cpp ZpKaratsubaElement.cpp) 
add_executable(MicroBench PackedSS.hpp TemplateField.cpp MicroBenchTest.cpp ZpKaratsubaElement.cpp) 

TARGET_LINK_LIBRARIES(PackedSSTest $ENV{HOME}/libscapi/install/lib/libntl.a
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        libboost_system.a libboost_thread.a pthread crypto dl ssl z)

TARGET_LINK_LIBRARIES(MicroBench $ENV{HOME}/libscapi/install/lib/libntl.a
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        libboost_system.a libboost_thread.a pthread crypto dl ssl z)
