set(SRC engine.c
        file.c
        sdf_interface.c
        rsa.c
        ecc.c
        log.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINUX -DBUILD_DEBUG")

add_library(securityEngine ${SRC})
target_link_libraries(securityEngine pthread ssl crypto bydsoftSDF)
install(TARGETS securityEngine DESTINATION lib)