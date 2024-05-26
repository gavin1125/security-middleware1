set(SRC engine.c
        file.c
        sdf_interface.c
        sdf_interface.h
        rsa.c
        rsa.h
        ecc.c
        ecc.h)

add_library(securityEngine ${SRC})
target_link_libraries(securityEngine pthread ssl crypto bydsoftSDF)
install(TARGETS securityEngine DESTINATION lib)