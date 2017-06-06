
include_directories(include/)
include_directories(../cloudUtils/include)
include_directories(../cloudDB/include)
include_directories(../libCloudGatewayMonitor/include)

file (GLOB_RECURSE
     source_files
     *.c
     )

add_library(cgsm SHARED ${source_files})

target_link_libraries(cgsm
                      cgdb
                      cloudutils
                      cloudutils_advanced_file_ops
                      cloudutils_aio
                      cloudutils_configuration
                      cloudutils_crypto
                      cloudutils_encoding
                      cloudutils_event
                      cloudutils_json
                      cloudutils_http
                      cloudutils_system
                      cloudutils_xml
                      cgmonitor
                      dl)

set_target_properties(cgsm PROPERTIES VERSION 0.1 SOVERSION 1)

install(TARGETS cgsm
                LIBRARY DESTINATION lib
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
