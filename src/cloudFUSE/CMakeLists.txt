
include_directories(../libCloudGatewayStorageManagerClient/include)
include_directories(../cloudUtils/include)
include_directories(.)

add_library(cgfs STATIC cgfs.c cgfs_async.c cgfs_cache.c cgfs_inode.c cgfs_file_handler.c cgfs_utils.c )

add_target(cloudFUSE_low cgfs cgsmclient_async cloudutils cloudutils_aio cloudutils_event fuse)
