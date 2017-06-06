cmake_minimum_required(VERSION 2.8)

project(CloudGW C)

if (NOT DEFINED ENV{COMPILER})
   #set(CMAKE_C_COMPILER "/usr/lib/clang/ccc-analyzer")
   set(CMAKE_C_COMPILER "gcc")
   #set(CMAKE_C_COMPILER "clang")
else()
   set(CMAKE_C_COMPILER "$ENV{COMPILER}")
endif()

option(ENABLE_COVERAGE "Enable Code Coverage" OFF)
option(ENABLE_ASAN "Enable Address Sanitizer" OFF)

set(CMAKE_C_FLAGS "$ENV{CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "$ENV{LDFLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "$ENV{LDFLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "$ENV{LDFLAGS}")

LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/CMakeModules/")

if(CMAKE_COMPILER_IS_GNUCC OR ${CMAKE_C_COMPILER} STREQUAL "clang")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wstrict-aliasing -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int -Werror-implicit-function-declaration -Wparentheses -Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused -Wunknown-pragmas -Wfloat-equal -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wwrite-strings -Wsign-compare -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn -Wformat -Wmissing-format-attribute -Wno-deprecated-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wconversion -pipe -Wextra -Wcast-align -Wno-missing-field-initializers -Wmain -Waddress -Wunused-macros -fstack-protector -fPIC -fvisibility=hidden")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,relro,-z,now")

    if (${CMAKE_C_COMPILER} STREQUAL "gcc")
        message(STATUS "Compiler is GCC")
        # Always generate debug information, so it will remain available in separate file even after strip
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb3")

        if("${CMAKE_C_COMPILER_VERSION}" VERSION_EQUAL "4.9.0" OR "${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER "4.9.0")
            message(STATUS "Colorized diagnostics are ON")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdiagnostics-color=auto")
        endif()
    elseif(${CMAKE_C_COMPILER} STREQUAL "clang")
        message(STATUS "Compiler is Clang")
        # Always generate debug information, so it will remain available in separate file even after strip
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wassign-enum -Wnewline-eof -Wextra-semi -Wmissing-variable-declarations")
    else()
        message(STATUS "Compiler is other : ${CMAKE_C_COMPILER}")
        # Always generate debug information, so it will remain available in separate file even after strip
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3")
    endif()

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")

        message(STATUS "Release build")

        set(CMAKE_C_FLAGS_RELEASE "-D_FORTIFY_SOURCE=2 -O3 -Wuninitialized -DNDEBUG")

        if (DEFINED ENV{DEBUG_OBJECTS_PATH})
                set(CMAKE_C_LINK_EXECUTABLE
                        "${CMAKE_C_LINK_EXECUTABLE}"
                        "${CMAKE_OBJCOPY} --only-keep-debug <TARGET> $ENV{DEBUG_OBJECTS_PATH}/<TARGET>.debug"
                        "${CMAKE_OBJCOPY} --strip-debug <TARGET>"
                        "${CMAKE_OBJCOPY} --add-gnu-debuglink=$ENV{DEBUG_OBJECTS_PATH}/<TARGET>.debug <TARGET>")

                 set(CMAKE_C_CREATE_SHARED_LIBRARY
                        "${CMAKE_C_CREATE_SHARED_LIBRARY}"
                        "${CMAKE_OBJCOPY} --only-keep-debug <TARGET> $ENV{DEBUG_OBJECTS_PATH}/<TARGET>.debug"
                        "${CMAKE_OBJCOPY} --strip-debug --strip-unneeded <TARGET>"
                        "${CMAKE_OBJCOPY} --add-gnu-debuglink=$ENV{DEBUG_OBJECTS_PATH}/<TARGET>.debug <TARGET>")

                 set(CMAKE_C_CREATE_SHARED_MODULE
                        "${CMAKE_C_CREATE_SHARED_MODULE}"
                        "${CMAKE_OBJCOPY} --only-keep-debug <TARGET> $ENV{DEBUG_OBJECTS_PATH}/<TARGET>.debug"
                        "${CMAKE_OBJCOPY} --strip-debug --strip-unneeded <TARGET>"
                        "${CMAKE_OBJCOPY} --add-gnu-debuglink=$ENV{DEBUG_OBJECTS_PATH}/<TARGET>.debug <TARGET>")
        else (DEFINED ENV{DEBUG_OBJECTS_PATH})
             set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-s")
             set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "-s")
             set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "-s")
        endif (DEFINED ENV{DEBUG_OBJECTS_PATH})

        if (${CMAKE_C_COMPILER} STREQUAL "gcc")

            if (DEFINED CMAKE_C_COMPILER_VERSION)
                if ("${CMAKE_C_COMPILER_VERSION}" VERSION_EQUAL "4.6.0" OR "${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER "4.6.0")

                    message(STATUS "Enabling LTO")
                    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fuse-linker-plugin -flto")
                    set(CMAKE_AR "gcc-ar")
                    set(CMAKE_RANLIB "gcc-ranlib")

#                   set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wsuggest-attribute=const -Wsuggest-attribute=pure")

                    if("${CMAKE_C_COMPILER_VERSION}" VERSION_EQUAL "4.9.0" OR "${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER "4.9.0")
                        message(STATUS "Stack-protector-strong is ON")
                        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fstack-protector-strong")
                    endif()

                endif()
            endif()

        elseif(${CMAKE_C_COMPILER} STREQUAL "clang")

            message(STATUS "Enabling LTO")
            set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto")

            message(STATUS "Stack-protector-strong is ON")
            set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fstack-protector-strong")

        endif()

    else()

        message(STATUS "Debug build.")
        set(CMAKE_BUILD_TYPE "Debug")
        set(CMAKE_C_FLAGS_DEBUG "-O0 -fno-omit-frame-pointer -fstack-protector-all -DCGUTILS_TRACE_ENABLE=1  -DCGUTILS_DEBUG_ENABLE=1")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DUSE_DEV_URL_FOR_LICENSE_CHECK=1")

        if (${CMAKE_C_COMPILER} STREQUAL "gcc")

            if(DEFINED CMAKE_C_COMPILER_VERSION)

                message(STATUS "GCC version is ${CMAKE_C_COMPILER_VERSION}")
                if("${CMAKE_C_COMPILER_VERSION}" VERSION_EQUAL "4.8.0" OR "${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER "4.8.0")
                    if (ENABLE_ASAN)
                        message(STATUS "Address Sanitizer is ON")
                        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
                    endif(ENABLE_ASAN)

                    if("${CMAKE_C_COMPILER_VERSION}" VERSION_EQUAL "4.9.0" OR "${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER "4.9.0")
                        message(STATUS "UndefinedBehaviorSanitizer is ON")
                        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")
                    endif()

                endif()
            endif()

            if (ENABLE_COVERAGE)
                message(STATUS "Coverage is on.")
                set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} --coverage")
            endif()

        elseif(${CMAKE_C_COMPILER} STREQUAL "clang")

            # Not supported before LLVM 3.4
            message(STATUS "IntegerSanitizer is ON")
            message(STATUS "BoolSanitizer is ON")
            message(STATUS "BoundsSanitizer is ON")
            message(STATUS "EnumSanitizer is ON")
            message(STATUS "ObjectSizeSanitizer is ON")
            message(STATUS "functionSanitizer is ON")
            message(STATUS "UndefinedBehaviorSanitizer is ON")
            set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wunreachable-code -fsanitize=integer -fsanitize=undefined -fsanitize=bool -fsanitize=bounds -fsanitize=enum -fsanitize=object-size -fsanitize=function ")

            if (ENABLE_ASAN)
                message(STATUS "Address Sanitizer is ON")
                set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
            endif(ENABLE_ASAN)

        endif()

    endif()

endif()

# The explicit FILE_OFFSET_BITS is useless since it's already defined by LFS_CFLAGS
# when needed (which means it is not set on 64 bits hosts), but fuse is overcompensating something here.
add_definitions(-D_GNU_SOURCE=1 `getconf LFS_CFLAGS`  -D_FILE_OFFSET_BITS=64 )

execute_process(COMMAND hg id --id
                        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                        OUTPUT_FILE ${CMAKE_BINARY_DIR}/build-id
                        ERROR_QUIET
                        OUTPUT_STRIP_TRAILING_WHITESPACE)
install(FILES ${CMAKE_BINARY_DIR}/build-id
              DESTINATION share/cloudgateway/
              PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

macro(add_target new_target)
 add_executable(${new_target} "${new_target}.c")
 if(${ARGC} GREATER 1)
  target_link_libraries(${new_target} ${ARGN})
 endif()
 install(TARGETS ${new_target}
                 RUNTIME DESTINATION bin
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
endmacro()

macro(add_no_install_target new_target)
 add_executable(${new_target} "${new_target}.c")
 if(${ARGC} GREATER 1)
  target_link_libraries(${new_target} ${ARGN})
 endif()
endmacro()

set(CMAKE_SHARED_MODULE_PREFIX_C "")

macro(add_plugin new_target)
 add_library(${new_target} MODULE "${new_target}.c")
 if(${ARGC} GREATER 1)
  target_link_libraries(${new_target} ${ARGN})
 endif()
 install(TARGETS ${new_target}
                 LIBRARY DESTINATION lib
                 PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endmacro()

macro(add_lib new_target source_files dependencies)
 add_library(${new_target} SHARED ${source_files})
 target_link_libraries(${new_target} ${dependencies})
 install(TARGETS ${new_target}
                 LIBRARY DESTINATION lib
                 PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endmacro()

set(EXECUTABLE_OUTPUT_PATH bin)
set(LIBRARY_OUTPUT_PATH lib)

add_subdirectory(cloudDB)
add_subdirectory(cloudFUSE)
add_subdirectory(cloudGatewayStorageManager)
add_subdirectory(cloudStorageProviders)
add_subdirectory(cloudStorageFilters)
add_subdirectory(cloudUtils)
add_subdirectory(libCloudGatewayMonitor)
add_subdirectory(libCloudGatewayStorageManagerClient)
add_subdirectory(libCloudGatewayStorageManager)
add_subdirectory(scripts)
add_subdirectory(tests)
add_subdirectory(tools)

enable_testing()
add_test(cloudTEST tests/${EXECUTABLE_OUTPUT_PATH}/cloudTEST)
add_test(cloudDBtest tests/${EXECUTABLE_OUTPUT_PATH}/cloudDBtest)
add_test(cloudProviderTest tests/${EXECUTABLE_OUTPUT_PATH}/cloudProviderTest)
SET_TESTS_PROPERTIES(cloudTEST PROPERTIES FAIL_REGULAR_EXPRESSION "failed")
SET_TESTS_PROPERTIES(cloudDBtest PROPERTIES FAIL_REGULAR_EXPRESSION "failed")
SET_TESTS_PROPERTIES(cloudProviderTest PROPERTIES FAIL_REGULAR_EXPRESSION "failed")
