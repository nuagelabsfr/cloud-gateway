#!/bin/bash

readonly TEST_DIR=`dirname $0`

readonly PROJECT_PATH="${TEST_DIR}/../.."
readonly SOURCE_PATH=${PROJECT_PATH}/src
readonly BUILD_PATH=${PROJECT_PATH}/build
readonly CACHE_ROOT=/data/cloudgw_cache/

if [ -z "${BIN_PATH}" ]; then
    BIN_PATH="${BUILD_PATH}"
fi

readonly CG_STORAGE_MANAGER_BIN="${BIN_PATH}/cloudGatewayStorageManager/bin/cgStorageManager"
readonly CLOUD_FUSE_BIN="${BIN_PATH}/cloudFUSE/bin/cloudFUSE_low"
readonly SHOW_INSTANCES_BIN="${BIN_PATH}/tools/bin/cg_show_instances_for_file"
readonly MOUNT_POINT=/mnt/fuse/

readonly CONFIG_PATH="/home/remi/cloudGW/src/tests/configs/"
readonly CONFIG_FILE="${CONFIG_PATH}/CloudGatewayConfiguration.xml"
readonly FS_ID=$( ${BIN_PATH}/tools/bin/cg_config_get ${CONFIG_FILE} 'FileSystems/FileSystem/Id' )
readonly CLOUD_FUSE_PARAMETERS="-o default_permissions -o fsname=CloudGateway:vg_fuse -o allow_other -d ${MOUNT_POINT} -s ${CONFIG_FILE} -i ${FS_ID}"

readonly TEST_CONTENT="azertyazerty0xDEAD0xABAD1DEA"

readonly CG_STORAGE_MANAGER_SYMLINK_CONF="${CONFIG_PATH}/CloudGatewayConfiguration-Symlink.xml"
readonly CG_STORAGE_MANAGER_VALID_CONF="${CONFIG_PATH}/CloudGatewayConfiguration-Mirroring-Valid.xml"
readonly CG_STORAGE_MANAGER_FIRST_DOWN_CONF="${CONFIG_PATH}/CloudGatewayConfiguration-Mirroring-FirstInstanceDown.xml"
readonly CG_STORAGE_MANAGER_SECOND_DOWN_CONF="${CONFIG_PATH}/CloudGatewayConfiguration-Mirroring-SecondInstanceDown.xml"
readonly CG_STORAGE_MANAGER_ALL_DOWN_CONF="${CONFIG_PATH}/CloudGatewayConfiguration-Mirroring-AllInstancesDown.xml"

function fail()
{
    echo "Failed: $1";
    fusermount -u ${MOUNT_POINT}
    kill -USR1 `cat /tmp/CloudGatewayStorageManager.pid`
    exit 1;
}

function clean_cache()
{
    find /data/cloudgw_cache/ -type f -delete
#    rm -f /data/cloudgw_cache/*/*/*/*/*/*/*/*/* /data/cloudgw_cache/*/*/*/*
}

# Test setup

if [ ! -d ${SOURCE_PATH} ]; then
    fail "Source path ${SOURCE_PATH} does not exist.";
fi

if [ ! -d ${BUILD_PATH} ]; then
    fail "Source path ${SOURCE_PATH} does not exist.";
fi

if [ ! -d ${MOUNT_POINT} ]; then
    fail "Mount point ${MOUNT_POINT} does not exist.";
fi

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_VALID_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"

echo "Launch:\n ${CG_STORAGE_MANAGER_BIN} ${CG_STORAGE_MANAGER_SYMLINK_CONF}"
read ok
sleep 3

umask 0077

# Mount

${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1;

# List files in directory

ls -l ${MOUNT_POINT} > /dev/null

if [ $? -ne 0 ]; then
    fail "Directory listing failure.";
fi

# Cleanup existing file

if [ -f ${MOUNT_POINT}/testfile_failed ]; then
    rm -f ${MOUNT_POINT}/testfile_failed;
    if [ $? -ne 0 ]; then
        fail "File removal failure.";
    fi
fi

# Create the test file and check that we can access it

echo ${TEST_CONTENT} > ${MOUNT_POINT}/testfile_failed

if [ $? -ne 0 ]; then
    fail "File creation failure.";
fi

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# Wait before the file has been uploaded on all instances

DIRTY_COUNT=99
NB_RETRY=5

while [ ${DIRTY_COUNT} -gt 0 -a ${NB_RETRY} -gt 0 ]; do
    DIRTY_COUNT=$( ${SHOW_INSTANCES_BIN} ${CONFIG_FILE} ${FS_ID} /testfile_failed | grep 'dirty' | wc -l )
    NB_RETRY=$(( ${NB_RETRY} -1 ))
    sleep 5
done

if [ ${DIRTY_COUNT} -gt 0 ]; then
    fail "Test file has not been uploaded in time, something is wrong, exiting."
fi

# Remove the file from the cache

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_FIRST_DOWN_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# Ok, now we try to access the file (after cleaning the cache) while the first
# instance is having issues. We don't let enough time to the monitoring process
# to do its job.

sleep 3

# Mount
${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_SECOND_DOWN_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# Ok, now we try to access the file (after cleaning the cache) while the second
# instance is having issues. We don't let enough time to the monitoring process
# to do its job.

sleep 3

# Mount
${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_ALL_DOWN_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# Ok, now we try to access the file (after cleaning the cache) while all instances
# are down. Obviously this should fail. We don't let enough time to the monitoring process
# to do its job.

sleep 3

${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1;

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 1 ]; then
    fail "Reading file content should have failed with 1.";
fi

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_FIRST_DOWN_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# Ok, now we try to access the file (after cleaning the cache) while the first
# instance is having issues. This time we wait while the monitoring process
# checks taht the instances are ok.

sleep 20

${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1;

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_SECOND_DOWN_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# Ok, now we try to access the file (after cleaning the cache) while the second
# instance is having issues. This time we wait while the monitoring process
# checks taht the instances are ok.

sleep 20

${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1;

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_ALL_DOWN_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# Ok, now we try to access the file (after cleaning the cache) while all instances
# are down. Obviously this should fail. This time we wait while the monitoring process
# checks taht the instances are ok.

sleep 20

${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &
if [ $? -ne 0 ]; then
    fail "Cloud FUSE launch failure.";
fi
sleep 1;

clean_cache

CONTENT=`cat ${MOUNT_POINT}/testfile_failed 2>/dev/null`

if [ $? -ne 1 ]; then
    fail "Reading file content should have failed with 1.";
fi

# End of tests, cleaning up

rm -f ${MOUNT_POINT}/testfile_failed

# Unmount, otherwise the server is stuck
fusermount -u /mnt/fuse

rm -f "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
ln -s "${CG_STORAGE_MANAGER_VALID_CONF}" "${CG_STORAGE_MANAGER_SYMLINK_CONF}"
kill -HUP `cat /tmp/CloudGatewayStorageManager.pid`

# We need to launch a working Storage Manager, otherwise the
# test file will remain

sleep 15;

if [ $? -ne 0 ]; then
    fail "Unmount failure.";
fi

kill -USR1 `cat /tmp/CloudGatewayStorageManager.pid`

if [ $? -ne 0 ]; then
    fail "cgStorageManager stop failure.";
fi

echo "Success."
