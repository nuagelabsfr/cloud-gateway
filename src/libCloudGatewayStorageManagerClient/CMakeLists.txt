
include_directories(include/)
include_directories(../cloudUtils/include)
include_directories(../libCloudGatewayStorageManager/include)

add_library(cgsmclient_async SHARED cgsmc_async.c cgsmc_async_connection.c)

target_link_libraries(cgsmclient_async cloudutils cloudutils_configuration)

set_target_properties(cgsmclient_async PROPERTIES VERSION 0.1 SOVERSION 1)

install(TARGETS cgsmclient_async
                LIBRARY DESTINATION lib
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
