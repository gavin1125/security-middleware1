include_directories(../include)

add_executable(sslexample ssl_example.c)
target_link_libraries(sslexample curl securityEngine ssl crypto)
