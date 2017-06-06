#!/bin/bash

# Definitions
readonly SCRIPT_DIR=`dirname $0`/../../../bin
readonly ARGC="$#"
readonly PSQL_BINARY_NAME="psql"
readonly PSQL_CREATE_DB_FILE="create_pg_database.sql"

# First, try to set up env

if [ -f "${SCRIPT_DIR}/CloudGateway_env.sh" ]; then
    . "${SCRIPT_DIR}/CloudGateway_env.sh"
else
    echo "Unable to find Cloud Gateway environment file, exiting." 1>&2
    exit 1
fi

# Look for parameters
if [ "${ARGC}" -eq 1 ]; then
    readonly CONNECTION_STR="$1"

    PSQL=$(which ${PSQL_BINARY_NAME} 2>/dev/null )
    result=$?

    if [ ${result} -eq 0 ]; then
        if [ -f "${CG_RESOURCES_DIR}/${PSQL_CREATE_DB_FILE}" ]; then

            LD_LIBRARY_PATH= "${PSQL}" -q "${CONNECTION_STR}" < "${CG_RESOURCES_DIR}/${PSQL_CREATE_DB_FILE}"

            result=$?
            if [ "${result}" -eq 0 ]; then
                echo "Tables successfully created."
                substitute '__DB_CONNECTION_STRING__' "${CONNECTION_STR}" "${CG_STORAGE_MANAGER_CONFIG_FILE}"

                result=$?

                if [ "${result}" -eq 0 ]; then
                    echo "Configuration successfully updated."
                else
                    print_error "Error updating database configuration: ${result}"
                    exit ${result}
                fi
            else
                print_error "Error creating tables: ${result}."
                exit ${result}
            fi

        else
            print_error "PSQL database creation resource not found."
            exit 1
        fi
    else
        print_error "psql binary not found."
        exit 1
    fi
else
    print_error "Usage: $0 <Database Connection String>"
    exit 1
fi
