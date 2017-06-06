
include_directories(../cloudUtils/include)
include_directories(../libCloudGatewayStorageManager/include)
include_directories(../cloudDB/include)
include_directories(../libCloudGatewayMonitor/include)

add_plugin(cg_storage_provider_amazon cgsm cloudutils cloudutils_xml)

add_library(cg_storage_provider_openstack
            MODULE
            cg_storage_provider_openstack.c cg_storage_provider_openstack_auth.c )

target_link_libraries(cg_storage_provider_openstack cgsm cloudutils cloudutils_json cloudutils_xml)

install(TARGETS cg_storage_provider_openstack
                 LIBRARY DESTINATION lib
                 PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

add_plugin(cg_storage_provider_posix cgsm cloudutils)
