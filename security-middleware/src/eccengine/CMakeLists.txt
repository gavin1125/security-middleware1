include_directories(../include)

add_executable(eccenginetype1 eccengine_type1.c rsa.c sha1.c
)
target_link_libraries(eccenginetype1 curl ssl crypto sdf)

add_executable(pureeccengine pure_eccengine.c
)
target_link_libraries(pureeccengine curl ssl crypto)


add_executable(eccenginetype2 eccengine_type2.c rsa.c sha1.c
)
target_link_libraries(eccenginetype2 curl ssl crypto sdf)