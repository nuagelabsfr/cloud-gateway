#!/bin/bash

# Definitions

readonly SCRIPT_DIR=`dirname $0`
readonly ARGC="$#"
readonly ALLOW_ROOT="false"

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

if [ "${ARGC}" -eq 1 ]; then
    readonly MOUNT_POINT="$1"
    result=0
elif [ "${ARGC}" -eq 2 ]; then
    if [[ $1 == *.xml ]]; then
        # Looks like a config file
        readonly CG_CONFIG_FILE="$1"
        readonly MOUNT_POINT=$( get_configuration_value "${CG_CONFIG_FILE}" "//FileSystems/FileSystem[Id='${2}']/MountPoint" )
        result=$?
    else
        readonly CG_CONFIG_FILE="$2"
        readonly MOUNT_POINT=$( get_configuration_value "${CG_CONFIG_FILE}" "//FileSystems/FileSystem[Id='${1}']/MountPoint" )
        result=$?
    fi
fi

if [ ${result} -eq 0 -a -n "${MOUNT_POINT}" ]; then
    fusermount -u "${MOUNT_POINT}"

    result=$?
    if [ "${result}" -ne 0 ]; then
	print_error "Cloud Gateway Unmount failed with ${result}."
	exit ${result}
    fi
else
    print_error "Usage: $0 [<Mount point>|<Configuration File>]"
    exit 1
fi
