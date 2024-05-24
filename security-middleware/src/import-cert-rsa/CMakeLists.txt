#include_directories(${PROJECT_SOURCE_DIR}/soft-sdf/softalg)
#include_directories(${PROJECT_SOURCE_DIR}/soft-sdf/filesystem)
include_directories(../../3rd/soft-sdf)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -DLINUX -O3")


add_executable(importrsacert write_cert_rsa.c)
target_link_libraries(importrsacert bydsoftSDF ssl crypto)

add_executable(importecccert write_cert_ecc.c)
target_link_libraries(importecccert bydsoftSDF ssl crypto)


add_executable(ecctest ecc_test.c)
target_link_libraries(ecctest bydsoftSDF ssl crypto)