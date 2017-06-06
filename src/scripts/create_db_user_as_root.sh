#!/bin/bash

# Definitions
readonly SCRIPT_DIR=`dirname $0`/../../../bin
readonly ARGC="$#"
readonly PSQL_BINARY="psql"
readonly OPENSSL_BINARY="openssl"
readonly USER_PASSWORD_BYTES="48"
readonly NEW_USER_NAME="cloudgw_user"
readonly NEW_DB_NAME="cloudgw_db"
readonly NEW_USER_PASSWORD=`openssl rand -base64 ${USER_PASSWORD_BYTES}`
readonly DB_CONN_STR="host=localhost port=5432 user='${NEW_USER_NAME}' dbname='${NEW_DB_NAME}' password='${NEW_USER_PASSWORD}'"

# First, try to set up env

if [ -f "${SCRIPT_DIR}/CloudGateway_env.sh" ]; then
    . "${SCRIPT_DIR}/CloudGateway_env.sh"
else
    echo "Unable to find Cloud Gateway environment file, exiting." 1>&2
    exit 1
fi

PSQL=$(which ${PSQL_BINARY} 2>/dev/null )
result=$?

if [ ${result} -eq 0 ]; then

    echo "CREATE USER ${NEW_USER_NAME} WITH PASSWORD '${NEW_USER_PASSWORD}';" | su - postgres -c "${PSQL} -q"

    result=$?
    if [ "${result}" -eq 0 ]; then

        echo "Database user successfully created."

        echo "CREATE DATABASE ${NEW_DB_NAME} WITH TEMPLATE template0 OWNER=${NEW_USER_NAME} ENCODING='UTF8';" | su - postgres -c "${PSQL} -q"

        result=$?

        if [ "${result}" -eq 0 ]; then

            "$(dirname $0)/create_tables.sh" "${DB_CONN_STR}"
            result=$?

            if [ ${result} -eq 0 ]; then

                echo "Database successfully created."
            else
                print_error "Error creating tables: ${result}."
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
