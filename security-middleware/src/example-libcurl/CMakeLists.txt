add_executable(curldemo curl_demo.c)

target_link_libraries(curldemo curl securityEngine ssl crypto)