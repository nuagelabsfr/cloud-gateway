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
    print_error "Usage: $0 <inode number> <fs name> [-v] [-r]"
    exit 22
}

if [ $ARGC -lt 2 ]; then
    usage
fi

readonly inode_number=$1
[[ ${inode_number} =~ ^[0-9]+$ ]] || usage
shift

readonly fs_name=$1
[[ -n ${fs_name} ]] || usage
shift

VERBOSE=0
RAW=0
while true ; do
    if [ $# -eq 0 ]; then
        break;
    fi
    case "$1" in
        -v) VERBOSE=1; shift ;;
        -r) RAW=1; shift ;;
        --) shift ; break ;;
        *) usage;
    esac
done

if [ ${VERBOSE} -gt 0 ]; then
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

time_column="TO_CHAR(TO_TIMESTAMP(inodes.mtime), 'YYYY/MM/DD HH24:MI:SS') as mtime"
if [ ${RAW} -eq 1 ]; then
    time_column="inodes.mtime"
fi
size_column="pg_size_pretty(inodes.size) AS size"
if [ ${RAW} -eq 1 ]; then
    size_column="inodes.size AS size"
fi

request="
select filesystems.fs_name as FS, instance_name, $time_column,
CASE
  WHEN status=0 THEN
     'synced'
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
$size_column,
$full_path,
ii.id_in_instance

FROM inodes_instances AS ii
INNER JOIN inodes_instances_link AS iil ON (ii.inode_instance_id = iil.inode_instance_id)
INNER JOIN instances ON (ii.instance_id = instances.instance_id)
INNER JOIN inodes ON (inodes.inode_number = iil.inode_number AND inodes.fs_id = iil.fs_id)
INNER JOIN entries ON (entries.inode_number = iil.inode_number AND entries.fs_id = iil.fs_id)
INNER JOIN filesystems ON (entries.fs_id = filesystems.fs_id)
WHERE  filesystems.fs_name = '${fs_name}' AND inodes.inode_number = ${inode_number};"

get_psql_values "${request}" ${DISPLAY_PSQL_TABLE}
result=$?

exit ${result}
