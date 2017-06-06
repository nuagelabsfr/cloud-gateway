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

# Parse arguments

if [ "${ARGC}" -lt 1 -o "${ARGC}" -gt 2 ]; then
    print_error "Usage: ./CloudGatewayVolumeSize (--all-fs|--total|FS_NAME) [-v]"
    exit 22
fi

readonly FS_NAME=$(echo ${1} | tr -d "'\"")

if [ "${ARGC}" -eq 2 -a "$2" = "-v" ]; then
    readonly VERBOSE=1
else
    readonly VERBOSE=0
fi

additional_conditions=''
if [ "${FS_NAME}" != '--all-fs' -a "${FS_NAME}" != '--total' ]; then
    additional_conditions=" WHERE fs_name LIKE '${FS_NAME}' "
fi

pretty_size_print="pg_size_pretty"
if [ ${VERBOSE} -eq 1 ]; then
    pretty_size_print=""
fi

if [ "${FS_NAME}" != '--total' ]; then
    get_psql_values "
SELECT fs_name, ${pretty_size_print}(sum(size)::bigint) AS total_size, count(inodes.fs_id) AS nb_files
FROM inodes INNER JOIN filesystems ON filesystems.fs_id = inodes.fs_id
${additional_conditions}
GROUP BY filesystems.fs_id
ORDER BY fs_name" ${DISPLAY_PSQL_HEADER}
else
    get_psql_values "
SELECT '*ALL-FS*' as fs_name, ${pretty_size_print}(sum(size)::bigint) AS total_size, count(inodes.fs_id) AS nb_files
FROM inodes" ${DISPLAY_PSQL_HEADER}
fi

exit 0
