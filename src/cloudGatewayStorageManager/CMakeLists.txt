
include_directories(../libCloudGatewayStorageManager/include/)
include_directories(../cloudUtils/include)
include_directories(../cloudDB/include)
include_directories(../libCloudGatewayMonitor/include)
include_directories(.)

add_executable(cgStorageManager
               cgStorageManager.c
               cgStorageManagerCleaner.c
               cgStorageManagerMonitor.c
               cgStorageManagerServer.c
               cgStorageManagerSyncer.c)

target_link_libraries(cgStorageManager cgdb cgsm cloudutils cloudutils_json cloudutils_system cgmonitor dl)

install(TARGETS cgStorageManager
                RUNTIME DESTINATION bin
                PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
