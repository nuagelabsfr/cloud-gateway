find_package(PostgreSQL REQUIRED)

include_directories(include/)
include_directories(../cloudUtils/include)
include_directories(${PostgreSQL_INCLUDE_DIRS})
#include_directories(../MongoAsynC/include)


add_library(cgdb SHARED cgdb.c cgdb_backend.c cgdb_sql.c cgdb_utils.c)
target_link_libraries(cgdb cloudutils dl)
set_target_properties(cgdb PROPERTIES VERSION 0.1 SOVERSION 1)
install(TARGETS cgdb
                LIBRARY DESTINATION lib
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

add_plugin(cgdb_pg cgdb cloudutils pq)
target_link_libraries(cgdb_pg cgdb cloudutils ${PostgreSQL_LIBRARIES})
