
include_directories(include)
include_directories(../cloudDB/include)
include_directories(../cloudUtils/include)
include_directories(../libCloudGatewayStorageManager/include)
include_directories(../libCloudGatewayStorageManagerClient/include)
include_directories(../libCloudGatewayMonitor/include)
include_directories(../cloudGatewayStorageManager)

add_target(cg_show_instances_for_file cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)

add_target(cg_check_pg_connstr cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)
add_target(cg_get_pg_version cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)

add_target(cg_get_volume_rights cloudutils cloudutils_configuration cloudutils_json cloudutils_xml cgsm)
add_target(cg_set_volume_rights cloudutils cloudutils_configuration cloudutils_xml cgsm)

add_target(cg_storage_manager_config_test cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)

add_target(cg_decrypt_file cgsm cloudutils cloudutils_configuration cloudutils_xml)

add_target(cg_storage_list_containers cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)
add_target(cg_storage_get_container_stats cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)
add_target(cg_storage_create_container cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)
add_target(cg_storage_remove_empty_container cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_xml cgsm)

add_target(cg_config_get cloudutils cloudutils_configuration cloudutils_xml)
add_target(cg_config_set cloudutils cloudutils_xml)
add_target(cg_config_set_db cloudutils cloudutils_xml )

add_target(cg_config_add_filter_to_instance cloudutils cloudutils_xml )
add_target(cg_config_add_fs cloudutils cloudutils_xml )
add_target(cg_config_add_instance cloudutils cloudutils_xml )
add_target(cg_config_add_mount cloudutils cloudutils_configuration cloudutils_xml )

add_target(cg_config_list_fs cloudutils cloudutils_xml )
add_target(cg_config_list_instances cloudutils cloudutils_xml )

add_target(cg_config_remove_filter_from_instance cloudutils cloudutils_xml )
add_target(cg_config_remove_fs cloudutils cloudutils_xml )
add_target(cg_config_remove_instance cloudutils cloudutils_xml )

add_target(cg_config_show_fs cloudutils cloudutils_xml )
add_target(cg_config_show_instance cloudutils cloudutils_xml )
add_target(cg_config_show_mount cloudutils cloudutils_xml )

add_executable(cg_stats cg_stats.c tools_provider_stats_common.c)
target_link_libraries(cg_stats cloudutils cloudutils_configuration cloudutils_crypto cloudutils_http cloudutils_json cloudutils_xml cgsm cgmonitor)
install(TARGETS cg_stats
        RUNTIME DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

add_executable(cg_get_providers_stats cg_get_providers_stats.c tools_provider_stats_common.c)
target_link_libraries(cg_get_providers_stats cloudutils_configuration cgmonitor)
install(TARGETS cg_get_providers_stats
        RUNTIME DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

add_executable(cg_get_providers_stats_json cg_get_providers_stats_json.c tools_provider_stats_common.c)
target_link_libraries(cg_get_providers_stats_json cloudutils_configuration cloudutils_json cgmonitor)
install(TARGETS cg_get_providers_stats_json
        RUNTIME DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
