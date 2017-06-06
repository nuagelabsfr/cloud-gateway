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

function usage
{
    print_error "Usage: $0 [-v[v]]"
    exit 22
}

if [ $ARGC -gt 1 ]; then
    usage
fi

if [ $ARGC -eq 1 -a "$1" = "-vv" ]; then
    readonly VERBOSE=2
elif [ $ARGC -eq 1 -a "$1" = "-v" ]; then
    readonly VERBOSE=1
elif [ $ARGC -eq 1 ]; then
    usage
else
    readonly VERBOSE=0
fi


# Get dirty / deleting files count from DB
nb_dirty_files=0
nb_files_to_be_deleted=0

# Dirty
value=$( get_psql_single_value 'select count(*) from inodes_instances WHERE status = 1;' )
result=$?

if [ $? -eq 0 -a -n "${value}" ]; then
    readonly nb_dirty_files=${value}
else
    print_error "Error getting dirty files count: ${result}"
    readonly nb_dirty_files=0
fi

# Deleting
value=$( get_psql_single_value 'select count(*) from inodes_instances WHERE status = 2;' )
result=$?

if [ $? -eq 0 -a -n "${value}" ]; then
    readonly nb_files_to_be_deleted=${value}
else
    print_error "Error getting deleting files count: ${result}"
    readonly nb_files_to_be_deleted=0
fi

# If we have neither dirty nor deleted files, exit with 0.
if [ ${nb_dirty_files} -eq 0 -a ${nb_files_to_be_deleted} -eq 0 ]; then
    exit 0
fi

# Print counters
if [ ${nb_dirty_files} -gt 0 ]; then
    echo "${nb_dirty_files} files to upload.";
fi
if [ ${nb_files_to_be_deleted} -gt 0 ]; then
    echo "${nb_files_to_be_deleted} files to delete."
fi

# If we are in verbose mode, query then print content
if [ ${VERBOSE} -gt 0 ]; then
    if [ ${nb_files_to_be_deleted} -gt 0 ]; then
        result=$( get_psql_values "select iil.fs_id as FS, iil.inode_number, instances.instance_name,
    CASE WHEN deleting='t' THEN 'deleting'
         ELSE 'to_be_deleted'
    END
AS status
FROM inodes_instances AS ii
INNER JOIN inodes_instances_link AS iil ON (iil.inode_instance_id = ii.inode_instance_id)
INNER JOIN instances ON (ii.instance_id = instances.instance_id)
WHERE status = 2;" ${DISPLAY_PSQL_TABLE})
        returned_value=$?
        echo "${result}" >&2
    fi

    if [ ${nb_dirty_files} -gt 0 ]; then

        if [ ${VERBOSE} -gt 1 ]; then
            full_path="
(SELECT sub.path from (WITH RECURSIVE path(name, path, parent, entry_id, parent_id) AS (
          SELECT name, '/', NULL, entries.entry_id, CAST(0 as BIGINT) FROM entries WHERE entries.parent_entry_id IS NULL
          UNION
          SELECT
            entries.name,
            parentpath.path ||
              CASE parentpath.path
                WHEN '/' THEN ''
                ELSE '/'
              END || entries.name,
            parentpath.path, entries.entry_id, parent_entry_id as parent_id
          FROM entries, path as parentpath
          WHERE  entries.parent_entry_id = parentpath.entry_id)
        SELECT * FROM path WHERE entry_id = entries.entry_id) as sub) as path
"
        else
            full_path="entries.name";
        fi

        result=$( get_psql_values "
select filesystems.fs_name as FS, inodes.inode_number, instance_name, inodes.mtime, pg_size_pretty(inodes.size) AS size,
CASE
  WHEN status=1 THEN
    CASE WHEN uploading='t' THEN 'uploading'
         ELSE 'to_be_uploaded'
    END
  WHEN status=2 THEN
    CASE WHEN deleting='t' THEN 'deleting'
         ELSE 'to_be_deleted'
    END
END

 AS status,
$full_path
 FROM inodes_instances AS ii
INNER JOIN inodes_instances_link AS iil ON (ii.inode_instance_id = iil.inode_instance_id)
INNER JOIN instances ON (ii.instance_id = instances.instance_id)
INNER JOIN inodes ON (inodes.inode_number = iil.inode_number AND inodes.fs_id = iil.fs_id)
INNER JOIN entries ON (entries.inode_number = iil.inode_number AND entries.fs_id = iil.fs_id)
INNER JOIN filesystems ON (entries.fs_id = filesystems.fs_id)
WHERE status != 0;" ${DISPLAY_PSQL_TABLE})
        returned_value=$?
        echo "${result}" >&2
    fi
fi

# Different exit codes for each situation (dirty files only, deleted files only, both)
if [ ${nb_dirty_files} -gt 0 -a ${nb_files_to_be_deleted} -gt 0 ]; then
    exit 3
elif [ ${nb_files_to_be_deleted} -gt 0 ]; then
    exit 2
elif [ ${nb_dirty_files} -gt 0 ]; then
    exit 1
fi

exit 0
