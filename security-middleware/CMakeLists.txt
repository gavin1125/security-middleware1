cmake_minimum_required(VERSION 3.1)
project(security-middleware C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 99)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

include_directories(src/include)

add_subdirectory(src/engine)
add_subdirectory(src/eccengine)
add_subdirectory(3rd/soft-sdf)
add_subdirectory(src/example-ssl-rsa)
add_subdirectory(src/example-ssl-ecc)
add_subdirectory(src/example-libcurl)
add_subdirectory(src/import-cert-rsa)
add_subdirectory(src/security-engine-ecc)