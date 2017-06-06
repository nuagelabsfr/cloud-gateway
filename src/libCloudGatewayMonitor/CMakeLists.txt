
include_directories(include/)
include_directories(../cloudUtils/include)

file (GLOB_RECURSE
     source_files
     *.c
     )

add_library(cgmonitor SHARED ${source_files})

target_link_libraries(cgmonitor cloudutils cloudutils_shm)

set_target_properties(cgmonitor PROPERTIES VERSION 0.1 SOVERSION 1)

install(TARGETS cgmonitor
                LIBRARY DESTINATION lib
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
