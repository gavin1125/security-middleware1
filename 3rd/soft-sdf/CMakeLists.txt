include_directories(softalg)
include_directories(filesystem)
include_directories(.)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -DLINUX -O3")

set(src
        sdf_dev.c
        initfile.c
        filesystem/file.c
        filesystem/bit.c
        filesystem/fs.c
        softalg/rsa.c
        softalg/sha1.c
        softalg/sha2.c
        softalg/hmac_sha2.c
        softalg/hmac.c
        softalg/aes.c
        softalg/sm4.c
        softalg/sm2_alg.c
        softalg/sm3_alg.c
        softalg/soft_ecc.c
        softalg/soft_bigint.c
        tool.c
        log.c
        sesskeymgr.c
        softalg.c

)

add_library(bydsoftSDF ${src})
target_link_libraries(bydsoftSDF pthread dl)
install(TARGETS bydsoftSDF DESTINATION lib)


add_executable(sdftest sdf_test.c)
target_link_libraries(sdftest bydsoftSDF)


add_executable(rsatest rsa_test.c)
target_link_libraries(rsatest bydsoftSDF ssl crypto)

#add_executable(importkey rsa_import_private_key.c)
#target_link_libraries(importkey bydsoftSDF ssl crypto)
#
#add_executable(writecert ../src/import-cert-rsa/write_cert_rsa.c)
#target_link_libraries(writecert bydsoftSDF ssl crypto)