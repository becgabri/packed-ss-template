# https://stackoverflow.com/questions/46906674/how-can-i-use-add-library-in-cmakelists-txt-to-include-entire-files-cpp-h-et
file(GLOB_RECURSE SOME_HEADERS "*.hpp")
file(GLOB_RECURSE OTHER_HEADERS "*.h")
file(GLOB_RECURSE CPP "*.cpp")

add_library(libscapi_utils ${SOME_HEADERS} ${OTHER_HEADERS} ${CPP})
# https://stackoverflow.com/questions/20746936/what-use-is-find-package-when-you-need-to-specify-cmake-module-path
#target_include_directories(libscapi_utils PUBLIC ${NTL_INCLUDE_DIR})
target_link_libraries(libscapi_utils OpenSSL::Crypto ${NTL_LIB})
