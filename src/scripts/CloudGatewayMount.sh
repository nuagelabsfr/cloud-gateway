#!/bin/bash

# Definitions

readonly SCRIPT_DIR=`dirname $0`
readonly ARGC="$#"
readonly ALLOW_ROOT="false"
FUSE_OPTIONS="-o default_permissions -o allow_other -o big_writes"

# First, try to set up env

if [ -f "${SCRIPT_DIR}/CloudGateway_env.sh" ]; then
    . "${SCRIPT_DIR}/CloudGateway_env.sh"
else
    echo "Unable to find Cloud Gateway environment file, exiting." 1>&2
    exit 1
fi

# Check that we are not root

if [ "${EUID}" -eq 0 -a "${ALLOW_ROOT}" != 'true' ]; then
    print_error "$0 should not be started as root."
    exit 1
fi

# Look for parameters
result=2

if [ "${ARGC}" -eq 2 ]; then
    if [[ $1 == *.xml ]]; then
        # Looks like a config file
        readonly FS_ID="$2"
        readonly CG_CONFIG_FILE="$1"
    else
        readonly FS_ID="$1"
        readonly CG_CONFIG_FILE="$2"
    fi
    readonly MOUNT_POINT=$( get_configuration_value "${CG_CONFIG_FILE}" "//FileSystems/FileSystem[Id='${FS_ID}']/MountPoint" )
    result=$?
fi


if [ ${result} -eq 0 -a -n "${MOUNT_POINT}" ]; then
    FUSE_OPTIONS="${FUSE_OPTIONS} -o fsname=CloudGateway:${FS_ID}"

    "${CG_INSTALLATION_DIR}/bin/cloudFUSE_low" ${FUSE_OPTIONS}  -s "${CG_CONFIG_FILE}" -i "${FS_ID}" "${MOUNT_POINT}"

    result=$?
    if [ "${result}" -eq 0 ]; then
	echo "Cloud Gateway Volume ${MOUNT_POINT} is ready."
    else
	print_error "Cloud Gateway Mount failed with ${result}."
	exit ${result}
    fi
else
    print_error "Usage: $0 <FS ID> <Configuration File>"
    exit 1
fi
