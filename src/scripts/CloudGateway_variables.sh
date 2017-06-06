#!/bin/bash

# Definitions
readonly CG_LIBRARY_DIR="${CG_INSTALLATION_DIR}/lib"
readonly CG_BIN_DIR="${CG_INSTALLATION_DIR}/bin"
readonly CG_RESOURCES_DIR="${CG_INSTALLATION_DIR}/share/cloudgateway/resources"
readonly CG_STORAGE_MANAGER_CONFIG_FILE="${CG_INSTALLATION_DIR}/etc/CloudGatewayConfiguration.xml"
readonly CG_STORAGE_MANAGER_PID_FILE_DEFAULT="${CG_INSTALLATION_DIR}/run/CloudGatewayStorageManager.pid"
readonly CG_STORAGE_MANAGER_XPATH_PID_FILE="General/PidFile"
readonly CG_STORAGE_MANAGER_XPATH_CONN_STR='DB/Specifics/ConnectionString'

readonly PSQL_BINARY="psql"

export LD_LIBRARY_PATH="${CG_LIBRARY_DIR}"
