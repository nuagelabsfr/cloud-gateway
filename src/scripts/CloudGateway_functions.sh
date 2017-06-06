#!/bin/bash

# Functions
print_error()
{
  echo "$@" 1>&2;
}

substitute()
{
    local readonly from=$1
    local readonly to=$2
    local readonly file=$3

    sed -i "s,${from},${to},g" "${file}"
}

get_configuration_value()
{
    local readonly configuration_file=$1
    local readonly xpath=$2

    "${CG_BIN_DIR}/cg_config_get" "${configuration_file}" "${xpath}"
}

get_psql_single_value()
{
    local readonly query=$1
    local readonly connstr=$( get_configuration_value "${CG_STORAGE_MANAGER_CONFIG_FILE}" "${CG_STORAGE_MANAGER_XPATH_CONN_STR}" )
    local result=$?

    local readonly PSQL=$(which ${PSQL_BINARY} 2>/dev/null )
    
    if [ ${result} -eq 0 -a -n "${connstr}" ]; then
        value=$( ${PSQL} -t -c "${query}" "${connstr}"| awk '{print $1}' )
        result=$?

        if [ ${result} -eq 0 -a -n "${value}" ]; then
            echo "${value}"
        else
            print_error "Error querying PSQL: ${result}"
        fi
    else
        print_error "Unable to retrieve connection string: ${result}."
    fi

    return ${result}
}

get_psql_values()
{
    local readonly query=$1
    local readonly display_psql_header=$2
    local readonly connstr=$( get_configuration_value "${CG_STORAGE_MANAGER_CONFIG_FILE}" "${CG_STORAGE_MANAGER_XPATH_CONN_STR}" )
    local result=$?

    local psql_options=""

    local readonly PSQL=$(which ${PSQL_BINARY} 2>/dev/null )

    if [ ! -n "${display_psql_header}" -a "${display_psql_header}" != "0" ]; then
	psql_options="${psql_options} -t"
    fi

    if [ ${result} -eq 0 -a -n "${connstr}" ]; then
        value=$( ${PSQL} ${psql_options} -c "${query}" "${connstr}" )
        result=$?

        if [ ${result} -eq 0 ]; then
            echo "${value}" | grep -v '^$'
        else
            print_error "Error querying PSQL: ${result}"
        fi
    else
        print_error "Unable to retrieve connection string: ${result}."
    fi

    return ${result}
}

get_storage_manager_pid()
{
    local result=0
    local pid_file=$(get_configuration_value "${CG_STORAGE_MANAGER_CONFIG_FILE}" "${CG_STORAGE_MANAGER_XPATH_PID_FILE}")

    if [ "$?" -ne 0 -o -z "${pid_file}" ]; then
	local pid_file="${CG_STORAGE_MANAGER_PID_FILE_DEFAULT}"
    fi

    if [ -f "${pid_file}" ]; then
	local readonly pid=`cat ${pid_file}`

	if [ -n "${pid}" ]; then
	    result="${pid}"
	fi
    fi

    echo "${result}"
}

is_storage_manager_running()
{
    local result=0
    local pid=$(get_storage_manager_pid)

    if [ -n "${pid}" -a "${pid}" -ne 0 ]; then

	kill -0 "${pid}"

	if [ "$?" -eq 0 ]; then
	    result=1
	fi
    fi

    return ${result}
}

start_storage_manager()
{
    "${CG_BIN_DIR}/cgStorageManager" "${CG_STORAGE_MANAGER_CONFIG_FILE}"
}

stop_storage_manager()
{
    readonly pid=$(get_storage_manager_pid)

    if [ -n "${pid}" ]; then
	kill ${pid}
	result=$?
    else
	print_error "Unable to get Storage Manager pid."
    fi
}

stop_storage_manager_gracefully()
{
    readonly pid=$(get_storage_manager_pid)

    if [ -n "${pid}" ]; then
	kill -USR1 ${pid}
	result=$?
    else
	print_error "Unable to get Storage Manager pid."
    fi
}

reload_storage_manager()
{
    readonly pid=$(get_storage_manager_pid)

    if [ -n "${pid}" ]; then
	kill -HUP ${pid}
	result=$?
    else
	print_error "Unable to get Storage Manager pid."
    fi
}
