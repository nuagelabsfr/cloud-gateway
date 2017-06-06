/*
 * This file is part of Nuage Labs SAS's Cloud Gateway.
 *
 * Copyright (C) 2011-2017  Nuage Labs SAS
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifndef DELAYED_ENTRIES_COMMON_H_
#define DELAYED_ENTRIES_COMMON_H_

static inline void delayed_entries_common_print_header(void)
{
    fprintf(stdout,
            "%-20s %-25s %-25s %-10s %-20s %-20s %-20s %-25s %s\n",
            "Inode Number",
            "Deletion time",
            "Delete After",
            "Size",
            "Owner",
            "Group",
            "Mode",
            "Modification Time",
            "Path"
        );
}

static inline void delayed_entry_to_str(cgdb_delayed_expunge_entry const * const delayed_entry,
                                        char ** const uid,
                                        char ** const gid,
                                        char ** const perms,
                                        char ** const deletion_time_str,
                                        char ** const delete_after_str,
                                        char ** const mtime_str)
{
    CGUTILS_ASSERT(delayed_entry);
    CGUTILS_ASSERT(uid != NULL);
    CGUTILS_ASSERT(gid != NULL);
    CGUTILS_ASSERT(perms != NULL);
    CGUTILS_ASSERT(deletion_time_str != NULL);
    CGUTILS_ASSERT(delete_after_str != NULL);
    CGUTILS_ASSERT(mtime_str != NULL);

    cgdb_entry const * const entry = &(delayed_entry->entry);
    cgdb_inode const * const inode = &(entry->inode);
    size_t uid_size = 0;
    size_t gid_size = 0;
    size_t perms_size = 0;
    char * tmp_uid = NULL;
    char * tmp_gid = NULL;

    int res = cgutils_system_get_mode_as_str(inode->st.st_mode,
                                             perms,
                                             &perms_size);

    if (res != 0)
    {
        fprintf(stderr,
                "Error getting str from perms: %s\n",
                strerror(res));
        *perms = NULL;
    }

    res = cgutils_system_get_uid_name(inode->st.st_uid,
                                      &tmp_uid,
                                      &uid_size);

    if (res != 0)
    {
        fprintf(stderr,
                "Error getting name from uid: %s\n",
                strerror(res));
        tmp_uid = NULL;
    }

    res = cgutils_asprintf(uid,
                           "%lld/%s",
                           (long long) inode->st.st_uid,
                           tmp_uid != NULL ? tmp_uid : "");

    if (res != 0)
    {
        fprintf(stderr,
                "Error allocating memory for uid: %s\n",
                strerror(res));
        *uid = NULL;
    }

    res = cgutils_system_get_gid_name(inode->st.st_gid,
                                      &tmp_gid,
                                      &gid_size);

    if (res != 0)
    {
        fprintf(stderr,
                "Error getting str from gid: %s\n",
                strerror(res));
        tmp_gid = NULL;
    }

    res = cgutils_asprintf(gid,
                           "%lld/%s",
                           (long long) inode->st.st_gid,
                           tmp_gid != NULL ? tmp_gid : "");

    if (res != 0)
    {
        fprintf(stderr,
                "Error allocating memory for gid: %s\n",
                strerror(res));
        *gid = NULL;
    }

    res = cgutils_time_to_str((time_t) delayed_entry->deletion_time,
                              deletion_time_str);

    if (res != 0)
    {
        fprintf(stderr,
                "Error converting deletion time: %s\n",
                strerror(res));
        *deletion_time_str = NULL;
    }

    res = cgutils_time_to_str((time_t) delayed_entry->delete_after,
                              delete_after_str);

    if (res != 0)
    {
        fprintf(stderr,
                "Error converting delete after date: %s\n",
                strerror(res));
        *delete_after_str = NULL;
    }

    res = cgutils_time_to_str(inode->st.st_mtime,
                              mtime_str);

    if (res != 0)
    {
        fprintf(stderr,
                "Error converting last modification date: %s\n",
                strerror(res));
        *mtime_str = NULL;
    }

    CGUTILS_FREE(tmp_uid);
    CGUTILS_FREE(tmp_gid);
}

static inline void delayed_entries_common_print_entry(cgdb_delayed_expunge_entry const * const delayed_entry)
{
    CGUTILS_ASSERT(delayed_entry);
    cgdb_entry const * const entry = &(delayed_entry->entry);
    cgdb_inode const * const inode = &(entry->inode);
    char * uid = NULL;
    char * gid = NULL;
    char * perms = NULL;
    char * deletion_time_str = NULL;
    char * delete_after_str = NULL;
    char * mtime_str = NULL;

    delayed_entry_to_str(delayed_entry,
                         &uid,
                         &gid,
                         &perms,
                         &deletion_time_str,
                         &delete_after_str,
                         &mtime_str);

    fprintf(stdout,
            "%-20"PRIu64" %-25s %-25s %-10zu %-20s %-20s %-20s %-25s %s\n",
            inode->inode_number,
            deletion_time_str != NULL ? deletion_time_str : "",
            delete_after_str != NULL ? delete_after_str : "",
            inode->st.st_size,
            uid != NULL ? uid : "",
            gid != NULL ? gid : "",
            perms != NULL ? perms : "",
            mtime_str != NULL ? mtime_str : "",
            delayed_entry->full_path
        );

    CGUTILS_FREE(uid);
    CGUTILS_FREE(gid);
    CGUTILS_FREE(perms);
    CGUTILS_FREE(mtime_str);
    CGUTILS_FREE(deletion_time_str);
    CGUTILS_FREE(delete_after_str);
}

#endif /* DELAYED_ENTRIES_COMMON_H_ */
