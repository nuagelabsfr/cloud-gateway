
install(PROGRAMS create_tables.sh create_db_user.sh create_db_user_as_root.sh
                 DESTINATION share/cloudgateway/bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

install(PROGRAMS CloudGateway_functions.sh CloudGateway_variables.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

configure_file(CloudGateway_env.sh.tmpl CloudGateway_env.sh
               @ONLY)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/CloudGateway_env.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

install(PROGRAMS CloudGatewayMount.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayMount)

install(PROGRAMS CloudGatewayUnmount.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayUnmount)

install(PROGRAMS CloudGatewayStorageManager.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayStorageManager)

install(PROGRAMS CloudGatewayAddFilesystem.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayAddFilesystem)

install(PROGRAMS CloudGatewayAddFilterToInstance.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayAddFilterToInstance)

install(PROGRAMS CloudGatewayAddInstance.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayAddInstance)

install(PROGRAMS CloudGatewayAddMount.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayAddMount)

install(PROGRAMS CloudGatewayInodeGetCachePath.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayInodeGetCachePath)

install(PROGRAMS CloudGatewayInodeInfos.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayInodeInfos)

install(PROGRAMS CloudGatewayListFilesystems.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayListFilesystems)

install(PROGRAMS CloudGatewayListInstances.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayListInstances)

install(PROGRAMS CloudGatewayRemoveFilesystem.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayRemoveFilesystem)

install(PROGRAMS CloudGatewayRemoveFilterFromInstance.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayRemoveFilterFromInstance)

install(PROGRAMS CloudGatewayRemoveInstance.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayRemoveInstance)

install(PROGRAMS CloudGatewayShowFilesystem.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayShowFilesystem)

install(PROGRAMS CloudGatewayShowInstance.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayShowInstance)

install(PROGRAMS CloudGatewayShowMount.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayShowMount)

install(PROGRAMS CloudGatewayStatus.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayStatus)

install(PROGRAMS CloudGatewayStorageManagerConfigTest.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayStorageManagerConfigTest)

install(PROGRAMS CloudGatewayVolumeSize.sh
                 DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
                 RENAME CloudGatewayVolumeSize)

install(FILES debian/init.d
              DESTINATION share/cloudgateway/resources
              PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

configure_file(debian/cloudgateway.service.tmpl debian/cloudgateway.service
               @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/debian/cloudgateway.service
              DESTINATION share/cloudgateway/resources
              PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

configure_file(debian/cloudgatewaymount@.service.tmpl debian/cloudgatewaymount@.service
               @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/debian/cloudgatewaymount@.service
              DESTINATION share/cloudgateway/resources
              PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES create_pg_database.sql debian/default
              DESTINATION share/cloudgateway/resources
              PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
