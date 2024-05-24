set(SRC security_engine.c
        front.c back.c log.c)

add_library(securityEngineEcc ${SRC})
target_link_libraries(securityEngineEcc pthread ssl crypto)
install(TARGETS securityEngineEcc DESTINATION lib)