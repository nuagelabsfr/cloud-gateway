#!/bin/bash
### BEGIN INIT INFO
# Provides:          cloudgateway
# Required-Start:    $network $local_fs
# Required-Stop:     $network $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Should-Start:      postgresql
# Short-Description: Cloud Gateway turns any Cloud storage into a local volume.
### END INIT INFO

NAME=cloudgateway
SCRIPTNAME=/etc/init.d/${NAME}

CLOUDGW_PATH=/opt/CloudGateway/
CLOUDGW_USER=cloudgw
CLOUDGW_MOUNTS=()

[ -r /etc/default/${NAME} ] && . /etc/default/${NAME}

BINARYPATH="${CLOUDGW_PATH}/bin/"
CONFPATH="${CLOUDGW_PATH}/conf/"
SOCKETPATH="${CLOUDGW_PATH}/run/"
CLOUDGW_MOUNT_BIN="${BINARYPATH}/CloudGatewayMount"
CLOUDGW_UNMOUNT_BIN="${BINARYPATH}/CloudGatewayUnmount"
CGSM_BIN="${BINARYPATH}/CloudGatewayStorageManager"

[ -x "${CGSM_BIN}" ] || exit 0

# Make sure that ${SOCKETPATH} exists
mkdir -p "${SOCKETPATH}"
chown -R "${CLOUDGW_USER}" "${SOCKETPATH}"

# Load the VERBOSE setting and other rcS variables
[ -r /lib/init/vars.sh ] && . /lib/init/vars.sh

. /lib/lsb/init-functions

if [ "${EUID}" -eq 0 ]; then
    readonly RUNNING_AS_ROOT=1
elif [ "$(id -u -n)" = "${CLOUDGW_USER}" ]; then
    readonly RUNNING_AS_ROOT=0
else
    log_failure_msg "Error, this script should be run either as root or as ${CLOUDGW_USER}."
    exit 255
fi

is_kernel_feature_present()
{
    # 0 means not present
    # 1 means statically linked in the kernel
    # 2 means is compiled as a module
    local module=$1
    local result=0
    local gz_config=0
    local config_file="/proc/config"

    if [ ! -f "${config_file}" ]; then
        if [ -f "/proc/config.gz" ]; then
            config_file="/proc/config.gz"
            gz_config=1
        elif [ -f "/boot/config-$(uname -r)" ]; then
            config_file="/boot/config-$(uname -r)"
        else
            return 0
        fi
    fi

    if [ ${gz_config} -eq 0 ]; then
        local type=$(grep -F "${module}" "${config_file}" | cut -d= -f2)
    else
        local type=$(zgrep -F "${module}" "${config_file}" | cut -d= -f2)
    fi

    if [ $? -eq 0 ]; then
        if [ "${type}" = "m" ]; then
            result=2
        elif [ "${type}" = "y" ]; then
            result=1
        fi
    fi

    return ${result}
}

is_kernel_module_loaded()
{
    local module=$1
    local result=0

    /bin/lsmod | grep -qF "${module}"
    result=$?

    return ${result}
}

if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
    # Make sure the kernel module FUSE is loaded
    modprobe fuse
else
    is_kernel_feature_present "FUSE_FS"
    res=$?

    if [ ${res} -eq 0 ]; then
        echo "Error, looks like the FUSE module has not been compiled for this kernel."
        exit 254
    elif [ ${res} -eq 2 ]; then
        is_kernel_module_loaded "fuse"
        res=$?

        if [ ${res} -ne 0 ]; then
            echo "Warning, the FUSE kernel module does not seem to be loaded."
        fi
    fi
fi

mount_volumes()
{
    local result=0
    local res=0

    if [ $? -eq 0 -a -x "${CLOUDGW_MOUNT_BIN}" -a ${#CLOUDGW_MOUNTS[@]} -gt 0 ]; then
        for mount_conf_file in ${CLOUDGW_MOUNTS[@]}; do
            if [ -f "${CONFPATH}/${mount_conf_file}" ]; then
                if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
                    su - "${CLOUDGW_USER}" -c "'${CLOUDGW_MOUNT_BIN}' '${CONFPATH}/${mount_conf_file}'"
                else
                    "${CLOUDGW_MOUNT_BIN}" "${CONFPATH}/${mount_conf_file}"
                fi
                res=$?

                if [ ${res} -ne 0 ]; then

                    log_failure_msg "Error mouting Cloud Gateway volume '${CONFPATH}/${mount_conf_file}': ${res}"

                    if [ ${result} -eq 0 ]; then
                        result=${res}
                    fi
                fi
            fi
        done
    fi

    return ${result}
}

unmount_volumes()
{
    local result=0
    local res=0

    if [ $? -eq 0 -a -x "${CLOUDGW_UNMOUNT_BIN}" -a ${#CLOUDGW_MOUNTS[@]} -gt 0 ]; then
        for mount_conf_file in ${CLOUDGW_MOUNTS[@]}; do
            if [ -f "${CONFPATH}/${mount_conf_file}" ]; then
                if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
                    su - "${CLOUDGW_USER}" -c "'${CLOUDGW_UNMOUNT_BIN}' '${CONFPATH}/${mount_conf_file}'"
                else
                    "${CLOUDGW_UNMOUNT_BIN}" "${CONFPATH}/${mount_conf_file}"
                fi
                res=$?

                if [ ${res} -ne 0 ]; then

                    log_failure_msg "Error unmouting Cloud Gateway volume '${CONFPATH}/${mount_conf_file}': ${res}"

                    if [ ${result} -eq 0 ]; then
                        result=${res}
                    fi
                fi
            fi
        done
    fi

    if [ ${result} -ne 0 ]; then
        log_failure_msg "Failed volumes are probably still in use or exported over NFS."
    fi

    return ${result}
}

start_all()
{
    local result=0

    # Start the Storage Manager
    if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
        su - "${CLOUDGW_USER}" -c "'${CGSM_BIN}' start"
    else
        "${CGSM_BIN}" start
    fi

    result=$?

    if [ ${result} -eq 0 ]; then
        # Mount configured volumes
        mount_volumes
        result=$?
    else
        log_failure_msg "Error starting the Cloud Gateway Storage Manager: ${result}"
    fi

    return ${result}
}

stop_all()
{
    local result=0

    # Unmount configured volumes
    unmount_volumes
    result=$?

    if [ ${result} -eq 0 ]; then

        # Then stop the Storage Manager
        if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
            su - "${CLOUDGW_USER}" -c "'${CGSM_BIN}' stop"
        else
            "${CGSM_BIN}" stop
        fi
        result=$?

        if [ ${result} -ne 0 ]; then
            log_failure_msg "Error stopping the Cloud Gateway Storage Manager: ${result}"
        fi
    else
        log_failure_msg "Error unmouting Cloud Gateway volumes, the Storage Manager will not be stopped: ${result}"
    fi

    return ${result}
}

force_stop_all()
{
    local result=0
    local volumes_result=0

    # Unmount configured volumes
    unmount_volumes
    volumes_result=$?

    if [ ${volumes_result} -ne 0 ]; then
        log_failure_msg "Error unmouting Cloud Gateway volumes, the Storage Manager will be stopped anyway: ${volumes_result}"
    fi

    # Then stop the Storage Manager
    if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
        su - "${CLOUDGW_USER}" -c "'${CGSM_BIN}' force-stop"
    else
        "${CGSM_BIN}" force-stop
    fi
    result=$?

    if [ ${result} -ne 0 ]; then
        log_failure_msg "Error stopping the Storage Manager: ${result}"
    elif [ ${volumes_result} -ne 0 ]; then
        result=${volumes_result}
    fi

    return ${result}
}

result=0

case "$1" in
    start)
        start_all
        result=$?
        ;;
    stop|graceful-stop)
        stop_all
        result=$?
        ;;
    force-stop)
        force_stop_all
        result=$?
        ;;
    restart)
        force_stop_all
        sleep 5
        start_all
        result=$?
        ;;
    status|reload)
        if [ ${RUNNING_AS_ROOT} -eq 1 ]; then
            su - "${CLOUDGW_USER}" -c "'${CGSM_BIN}' $1"
        else
            "${CGSM_BIN}" $1
        fi
        result=$?
        ;;
    *)
        echo "Usage: $SCRIPTNAME {start|stop|status|restart|reload|force-stop}"
        result=1
        ;;
esac

exit ${result}
