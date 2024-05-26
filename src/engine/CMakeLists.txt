set(SRC security_engine.c)

add_library(securityEngine ${SRC})
target_link_libraries(securityEngine pthread ssl crypto bydsoftSDF)
install(TARGETS securityEngine DESTINATION lib)