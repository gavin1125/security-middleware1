include_directories(../include)

add_executable(sslexampleecc ssl_example.c)
target_link_libraries(sslexampleecc curl securityEngineEcc ssl crypto)
