#!/bin/bash

# Definitions
readonly SCRIPT_DIR=`dirname $0`
readonly ARGC="$#"

# First, try to set up env
if [ -f "${SCRIPT_DIR}/CloudGateway_env.sh" ]; then
    . "${SCRIPT_DIR}/CloudGateway_env.sh"
else
    echo "Unable to find Cloud Gateway environment file, exiting." 1>&2
    exit 1
fi

function usage
{
    print_error "Usage: $0 <inode number> <fs name> "
    exit 22
}

if [ $ARGC -ne 2 ]; then
    usage
fi

readonly inode_number=$1
[[ ${inode_number} =~ ^[0-9]+$ ]] || usage
readonly fs_name=$2
[[ -n ${fs_name} ]] || usage

fs_id=$( get_psql_single_value "SELECT fs_id FROM filesystems WHERE fs_name = '${fs_name}'" 2>/dev/null)
result=$?
if [ ${result} -ne 0 ]; then
    print_error "SQL Error"
    usage
fi

if [ -z "${fs_id}" ]; then
    print_error "FS ${fs_name} not found"
    usage
fi


readonly cache_root=$( get_configuration_value "${CG_STORAGE_MANAGER_CONFIG_FILE}" "/Configuration/FileSystems/FileSystem[Id='${fs_name}']/CacheRoot" )

tmp_path=""
cache_file_name=$(echo -n "${fs_id}_${inode_number}" | LD_LIBRARY_PATH= openssl dgst -sha256 -binary | base64)
cache_file_name=$(echo "${cache_file_name}" | tr '/' '-')
for i in 0 1 2; do
    char=${cache_file_name:$i:${i+1}}
    tmp_path=${tmp_path}${char}/
done
tmp_path3=${tmp_path}/${cache_file_name}

if [ -e ${cache_root}/${tmp_path3} ]; then
    echo ${cache_root}/${tmp_path3}
else
    tmp_path=""
    for i in 0 1 2 3 4 5 6 7; do
        char=${cache_file_name:$i:${i+1}}
        tmp_path=${tmp_path}${char}/
    done
    tmp_path8=${tmp_path}/${cache_file_name}

    if [ -e ${cache_root}/${tmp_path8} ]; then
        echo ${cache_root}/${tmp_path8}
    else
        echo ${cache_root}/${tmp_path3}
    fi
fi
