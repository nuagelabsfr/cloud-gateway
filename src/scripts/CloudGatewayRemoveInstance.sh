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

"${CG_INSTALLATION_DIR}/bin/cg_config_remove_instance" "$@"
