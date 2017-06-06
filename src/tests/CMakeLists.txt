
include_directories(../libCloudGatewayStorageManager/include)
include_directories(../libCloudGatewayMonitor/include)
include_directories(../cloudUtils/include)
include_directories(../cloudDB/include)
include_directories(../cloudDB/)
include_directories(include)

add_no_install_target(cloudTEST
                      cloudutils cloudutils_aio cloudutils_advanced_file_ops cloudutils_configuration cloudutils_crypto cloudutils_event cloudutils_http cloudutils_xml cgsm)

add_no_install_target(cloudDBtest
                      cloudutils cloudutils_aio cloudutils_advanced_file_ops cloudutils_configuration cloudutils_crypto cloudutils_event cloudutils_http cloudutils_xml cgdb cgsm)

add_no_install_target(cloudProviderTest
                      cloudutils cloudutils_aio cloudutils_advanced_file_ops cloudutils_configuration cloudutils_crypto cloudutils_event cloudutils_http cloudutils_xml cgsm)

add_no_install_target(cloudOneProviderTest
                      cloudutils cloudutils_aio cloudutils_advanced_file_ops cloudutils_configuration cloudutils_crypto cloudutils_event cloudutils_http cloudutils_xml cgsm)

configure_file(CloudGatewayConfiguration.xml.tmpl CloudGatewayConfiguration.xml
               @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CloudGatewayConfiguration.xml
        DESTINATION etc
        RENAME CloudGatewayConfiguration.xml.sample
        PERMISSIONS OWNER_READ OWNER_WRITE)
