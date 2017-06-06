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
readonly MOUNT_POINT=/mnt/ftp

readonly CONFIG_FILE="${SOURCE_PATH}/tests/configs/CloudGatewayConfigurationPG.xml"
readonly FS_ID=$( ${BIN_PATH}/tools/bin/cg_config_get ${CONFIG_FILE} 'FileSystems/FileSystem/Id' )
readonly CLOUD_FUSE_PARAMETERS="-o default_permissions -o fsname=CloudGateway:vg_fuse -o allow_other ${MOUNT_POINT} -s ${CONFIG_FILE} -i ${FS_ID}"

readonly TEST_CONTENT="azertyazerty0xDEAD0xABAD1DEA"

function fail()
{
    echo "Failed: $1";
    fusermount -u ${MOUNT_POINT}
    kill -USR1 `cat /tmp/CloudGatewayStorageManager.pid`
    exit 1;
}

function clean_cache()
{
    find /data/Dumps/cloudgw_cache/ -type f -delete
#    rm -f /data/cloudgw_cache/*/*/*/*/*/*/*/*/* /data/cloudgw_cache/*/*/*/*
}

if [ ! -d ${SOURCE_PATH} ]; then
    fail "Source path ${SOURCE_PATH} does not exist.";
fi

if [ ! -d ${BUILD_PATH} ]; then
    fail "Source path ${SOURCE_PATH} does not exist.";
fi

if [ ! -d ${MOUNT_POINT} ]; then
    fail "Mount point ${MOUNT_POINT} does not exist.";
fi

if [ -z "${NO_STORAGE_MANAGER}" -o "${NO_STORAGE_MANAGER}" != "yes" ]; then
    ${CG_STORAGE_MANAGER_BIN} ${CONFIG_FILE} > /tmp/cg_storage_manager_log 2> /tmp/cg_storage_manager_err &

    if [ $? -ne 0 ]; then
        fail "CG Storage Manager launch failure.";
    fi
fi

sleep 1;

if [ -z "${NO_FUSE}" -o "${NO_FUSE}" != "yes" ]; then

    mount | grep -qF '${MOUNT_POINT}' > /dev/null
    if [ $? -eq 0 ]; then
        fail "Cloud FUSE already mounted.";
    fi

    ${CLOUD_FUSE_BIN} ${CLOUD_FUSE_PARAMETERS} > /tmp/cloud_fuse_log 2> /tmp/cloud_fuse_err &

    if [ $? -ne 0 ]; then
        fail "Cloud FUSE launch failure.";
    fi
fi

sleep 1;
umask 0077

# Listing entries

ls -l ${MOUNT_POINT} > /dev/null

if [ $? -ne 0 ]; then
    fail "Directory listing failure.";
fi

# Removing testfile if it exists

if [ -f ${MOUNT_POINT}/testfile ]; then
    rm -f ${MOUNT_POINT}/testfile;
    if [ $? -ne 0 ]; then
        fail "File removal failure.";
    fi
fi

# Testing directory mtime update on new file creation

DIR_MTIME_BEFORE=`stat -c '%Y' ${MOUNT_POINT}`

if [ $? -ne 0 -o -z "${DIR_MTIME_BEFORE}" ]; then
    fail "Directory mtime listing failure.";
fi

sleep 1

echo "" > ${MOUNT_POINT}/testfile

if [ $? -ne 0 ]; then
    fail "File creation failure.";
fi

DIR_MTIME_AFTER=`stat -c '%Y' ${MOUNT_POINT}`

if [ $? -ne 0 -o -z "${DIR_MTIME_AFTER}" ]; then
    fail "Directory mtime listing failure.";
fi

if [ "${DIR_MTIME_BEFORE}" = "${DIR_MTIME_AFTER}" ]; then
    fail "Directory mtime not modified";
fi

# Testing file mtime update on touch

touch ${MOUNT_POINT}/testfile

if [ $? -ne 0 ]; then
    fail "File touch failure.";
fi

touch ${MOUNT_POINT}/emptyfile

if [ $? -ne 0 ]; then
    fail "Empty file touch failure.";
fi

OUTPUT=`ls -l ${MOUNT_POINT} | grep testfile`

if [ $? -ne 0 ]; then
    fail "Directory listing failure.";
fi

if [ -z "${OUTPUT}" ]; then
    fail "Expected file is not present in directory listing.";
fi

# Test owner/group

OWNER=`stat ${MOUNT_POINT}/testfile -c '%U %G' | grep 'remi users'`

if [ $? -ne 0 -o -z "${OWNER}" ]; then
    fail "Owner group failure.";
fi

# Test permissions

RIGHTS=`stat ${MOUNT_POINT}/testfile -c '%A' | grep -- '-rw-------'`

if [ $? -ne 0 -o -z "${RIGHTS}" ]; then
    fail "Permissions failure.";
fi

OUTPUT=`ls -l ${MOUNT_POINT} | grep emptyfile`

if [ $? -ne 0 ]; then
    fail "Directory listing failure (empty file).";
fi

if [ -z "${OUTPUT}" ]; then
    fail "Expected empty file is not present in directory listing.";
fi

# Add content, wait until it synced,
# remove file from cache, get the content

echo ${TEST_CONTENT} > ${MOUNT_POINT}/testfile

if [ $? -ne 0 ]; then
    fail "Adding content to file failed.";
fi

DIRTY_COUNT=99
NB_RETRY=5

while [ ${DIRTY_COUNT} -gt 0 -a ${NB_RETRY} -gt 0 ]; do
    DIRTY_COUNT=$( ${SHOW_INSTANCES_BIN} ${CONFIG_FILE} ${FS_ID} /testfile | grep 'dirty' | wc -l )
    NB_RETRY=$(( ${NB_RETRY} -1 ))
    sleep 5
done

if [ ${DIRTY_COUNT} -gt 0 ]; then
    fail "Test file has not been uploaded in time, something is wrong, exiting."
fi

clean_cache

OUTPUT=`ls -l ${MOUNT_POINT} | grep testfile`

if [ $? -ne 0 ]; then
    fail "Directory listing failure.";
fi

CONTENT=`cat ${MOUNT_POINT}/testfile`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

# check owner / group is still correct

OWNER=`stat ${MOUNT_POINT}/testfile -c '%U %G' | grep 'remi users'`

if [ $? -ne 0 -o -z "${OWNER}" ]; then
    fail "Owner group failure.";
fi

# check permissions are still correct

RIGHTS=`stat ${MOUNT_POINT}/testfile -c '%A' | grep -- '-rw-------'`

if [ $? -ne 0 -o -z "${RIGHTS}" ]; then
    fail "Permissions failure.";
fi

# get empty file content

CONTENT=`cat ${MOUNT_POINT}/emptyfile`

if [ $? -ne 0 ]; then
    fail "Reading empty file content failure.";
fi

# Symlink

if [ -e ${MOUNT_POINT}/testlink ]; then
    rm -f ${MOUNT_POINT}/testlink;
    if [ $? -ne 0 ]; then
        fail "Link removal failure.";
    fi
fi

ln -s ${MOUNT_POINT}/testfile ${MOUNT_POINT}/testlink

if [ $? -ne 0 ]; then
    fail "Linking failure.";
fi

CONTENT=`cat ${MOUNT_POINT}/testlink`

if [ $? -ne 0 ]; then
    fail "Reading link content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in /link/.";
fi

# Hardlink

ln ${MOUNT_POINT}/testfile ${MOUNT_POINT}/testhardlink

if [ $? -ne 0 ]; then
    fail "Hard linking failure.";
fi

CONTENT=`cat ${MOUNT_POINT}/testhardlink`

if [ $? -ne 0 ]; then
    fail "Reading hardlink content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in /hardlink/.";
fi

rm ${MOUNT_POINT}/testlink

if [ $? -ne 0 ]; then
    fail "Removing link failure.";
fi

## Rename one of the entries pointing to the hardlink

mv ${MOUNT_POINT}/testfile ${MOUNT_POINT}/testfile_renamed

if [ $? -ne 0 ]; then
    fail "Renaming file failure.";
fi

OWNER=`stat ${MOUNT_POINT}/testfile_renamed -c '%U %G' | grep 'remi users'`

if [ $? -ne 0 -o -z "${OWNER}" ]; then
    fail "Owner group failure.";
fi

RIGHTS=`stat ${MOUNT_POINT}/testfile_renamed -c '%A' | grep -- '-rw-------'`

if [ $? -ne 0 -o -z "${RIGHTS}" ]; then
    fail "Permissions failure.";
fi

chmod o+r ${MOUNT_POINT}/testfile_renamed

if [ $? -ne 0 ]; then
    fail "Chmod file failure.";
fi

chown remi:audio ${MOUNT_POINT}/testfile_renamed

if [ $? -ne 0 ]; then
    fail "Chown file failure.";
fi

OUTPUT=`ls -l ${MOUNT_POINT} | grep testfile_renamed`

if [ $? -ne 0 ]; then
    fail "Directory listing failure.";
fi

OWNER=`stat ${MOUNT_POINT}/testfile_renamed -c '%U %G' | grep 'remi audio'`

if [ $? -ne 0 -o -z "${OWNER}" ]; then
    fail "Owner group failure.";
fi

RIGHTS=`stat ${MOUNT_POINT}/testfile_renamed -c '%A' | grep -- '-rw----r--'`

if [ $? -ne 0 -o -z "${RIGHTS}" ]; then
    fail "Permissions failure.";
fi

truncate ${MOUNT_POINT}/testfile_renamed -s 0

if [ $? -ne 0 ]; then
     fail "Truncating file failure.";
fi

rm ${MOUNT_POINT}/testfile_renamed

if [ $? -ne 0 ]; then
    fail "Removing file failure.";
fi

CONTENT=`cat ${MOUNT_POINT}/testhardlink`

if [ $? -ne 0 ]; then
    fail "Reading hardlink content failure.";
fi

if [ -n "${CONTENT}" ]; then
    fail "Expected content is not present in /hardlink/.";
fi

rm ${MOUNT_POINT}/testhardlink

if [ $? -ne 0 ]; then
    fail "Removing hardlink failure.";
fi

rm ${MOUNT_POINT}/emptyfile

if [ $? -ne 0 ]; then
    fail "Removing empty file failure.";
fi

if [ -d ${MOUNT_POINT}/testdir ]; then
    rm -rf ${MOUNT_POINT}/testdir

    if [ $? -ne 0 ]; then
        fail "Dir removal failure.";
    fi
fi

# mkdir

mkdir ${MOUNT_POINT}/testdir

if [ $? -ne 0 ]; then
    fail "Directory creation failure.";
fi

mkdir ${MOUNT_POINT}/testdir/testdir

if [ $? -ne 0 ]; then
    fail "Sub-directory creation failure.";
fi

rmdir ${MOUNT_POINT}/testdir/testdir

if [ $? -ne 0 ]; then
    fail "Sub-directory deletion failure.";
fi

echo "" > ${MOUNT_POINT}/testdir/afile

if [ $? -ne 0 ]; then
    fail "File creation in newly created directory failure.";
fi

if [ ! -f ${MOUNT_POINT}/testdir/afile ]; then
    fail "Accessing file in newly created directory failure;";
fi

LIST=`ls -l ${MOUNT_POINT}/testdir/ | grep ' afile$'`

if [ -z "${LIST}" ]; then
    fail "Listing file in newly created directory failure;";
else
    sleep 5;
fi

mv ${MOUNT_POINT}/testdir ${MOUNT_POINT}/testdirrenamed

if [ $? -ne 0 ]; then
    fail "Renaming subdir failed;";
fi

rm ${MOUNT_POINT}/testdirrenamed/afile

if [ $? -ne 0 ]; then
    fail "Removing file in subdir failed;";
fi

rmdir ${MOUNT_POINT}/testdirrenamed

if [ $? -ne 0 ]; then
    fail "Removing subdir failed;";
fi

sleep 10;

# Concurrent read requests for a file not present in cache

echo ${TEST_CONTENT} > ${MOUNT_POINT}/testfile_not_in_cache

if [ $? -ne 0 ]; then
    fail "Adding content to file failed.";
fi

DIRTY_COUNT=99
NB_RETRY=5

while [ ${DIRTY_COUNT} -gt 0 -a ${NB_RETRY} -gt 0 ]; do
    DIRTY_COUNT=$( ${SHOW_INSTANCES_BIN} ${CONFIG_FILE} ${FS_ID} /testfile_not_in_cache | grep 'dirty' | wc -l )
    NB_RETRY=$(( ${NB_RETRY} -1 ))
    sleep 5
done

if [ ${DIRTY_COUNT} -gt 0 ]; then
    fail "Test file has not been uploaded in time, something is wrong, exiting."
fi

clean_cache

OUTPUT=`ls -l ${MOUNT_POINT} | grep testfile_not_in_cache`

if [ $? -ne 0 ]; then
    fail "Directory listing failure.";
fi

PIDS=()
NB_CONCURRENT_ACCESSES=5
INDEX=0
while [ ${INDEX} -lt ${NB_CONCURRENT_ACCESSES} ]; do
    cat ${MOUNT_POINT}/testfile_not_in_cache > /dev/null &
    PIDS=("${PIDS[@]}" "$!")
    INDEX=$(( ${INDEX} + 1 ))
done

for process in ${PIDS[@]}; do
    wait "${process}"
    result=$?
    if [ ${result} -ne 0 ]; then
        fail "Process ${process} exited with $?";
    fi
done

CONTENT=`cat ${MOUNT_POINT}/testfile_not_in_cache`

if [ $? -ne 0 ]; then
    fail "Reading file content failure.";
fi

if [ "${CONTENT}" != "${TEST_CONTENT}" ]; then
    fail "Expected content is not present in file.";
fi

rm -f "${MOUNT_POINT}/testfile_not_in_cache"

# Write to a renamed file

for counter in $(seq 1 10); do echo -n ${counter}; sleep 1; done > "${MOUNT_POINT}/test_file_before_rename" &
PID=$!

mv "${MOUNT_POINT}/test_file_before_rename" "${MOUNT_POINT}/test_file_after_rename"

if [ $? -ne 0 ]; then
    fail "Rename failed.";
fi

wait "${PID}"
result=$?

if [ ${result} -ne 0 ]; then
    fail "Process ${PID} exited with $?";
fi

CONTENT=`cat ${MOUNT_POINT}/test_file_after_rename`

if [ $? -ne 0 ]; then
    fail "Reading renamed content failure.";
fi

if [ "${CONTENT}" != "12345678910" ]; then
    fail "Expected content is not present in renamed file.";
fi

rm -f "${MOUNT_POINT}/test_file_after_rename"

# Write to a removed file

for counter in $(seq 1 10); do echo -n ${counter}; sleep 1; done > "${MOUNT_POINT}/test_file_before_removal" &
PID=$!

rm -f "${MOUNT_POINT}/test_file_before_removal"

if [ $? -ne 0 ]; then
    fail "Removal failed.";
fi

wait "${PID}"
result=$?

if [ ${result} -ne 0 ]; then
    fail "Process ${PID} exited with $?";
fi

# End of tests, cleaning up

lsof ${MOUNT_POINT}
fusermount -u ${MOUNT_POINT}

if [ $? -ne 0 ]; then
    fail "Unmount failure.";
fi

sleep 10

kill -USR1 `cat /tmp/CloudGatewayStorageManager.pid`

if [ $? -ne 0 ]; then
    fail "cgStorageManager stop failure.";
fi

echo "Success."
