
include_directories(../cloudUtils/include)
include_directories(../libCloudGatewayStorageManager/include)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DZLIB_CONST")

add_plugin(cg_storage_filter_encryption cloudutils cloudutils_crypto)
add_plugin(cg_storage_filter_compression cloudutils z)
