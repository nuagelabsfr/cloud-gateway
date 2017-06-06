#!/bin/bash

# Definitions
readonly SCRIPT_DIR=`dirname $0`/../../../bin
readonly ARGC="$#"
readonly PSQL_BINARY_NAME="psql"

# First, try to set up env

if [ -f "${SCRIPT_DIR}/CloudGateway_env.sh" ]; then
    . "${SCRIPT_DIR}/CloudGateway_env.sh"
else
    echo "Unable to find Cloud Gateway environment file, exiting." 1>&2
    exit 1
fi

# Look for parameters
if [ "${ARGC}" -eq 4 ]; then
    readonly CONNECTION_STR="$1"
    readonly NEW_USER_NAME="$2"
    readonly NEW_USER_PASSWORD="$3"
    readonly NEW_DB_NAME="$4"

    PSQL=$(which ${PSQL_BINARY_NAME} 2>/dev/null )
    result=$?

    if [ ${result} -eq 0 ]; then
        echo "CREATE USER ${NEW_USER_NAME} WITH PASSWORD '${NEW_USER_PASSWORD}';" | LD_LIBRARY_PATH= "${PSQL}" "${CONNECTION_STR}"

        result=$?
        if [ "${result}" -eq 0 ]; then

            echo "Database user successfully created."

            echo "CREATE DATABASE ${NEW_DB_NAME} WITH OWNER=${NEW_USER_NAME} ENCODING='UTF8';" | LD_LIBRARY_PATH= "${PSQL}" "${CONNECTION_STR}"

            result=$?

            if [ "${result}" -eq 0 ]; then

                echo "ALTER SCHEMA public OWNER TO ${NEW_USER_NAME};" | LD_LIBRARY_PATH= "${PSQL}" "${CONNECTION_STR}" "${NEW_DB_NAME}"
                result=$?

                if [ ${result} -eq 0 ]; then

                    echo "Database successfully created."
                else
                    print_error "Error changing ownership: ${result}."
                    exit ${result}
                fi

            else
                print_error "Error creating database: ${result}."
                exit ${result}
            fi

        else
            print_error "Error creating database user: ${result}."
            exit ${result}
        fi
    else
        print_error "psql binary not found."
        exit 1
    fi
else
    print_error "Usage: $0 <Database Connection String> <New User Name> <New User Password> <New DB Name>"
    exit 1
fi
