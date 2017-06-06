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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cloudTest.h"

#include <cloudutils/cloudutils_event.h>

#include <cgdb/cgdb.h>
#include <cgdb/cgdb_backend.h>
#include <cgdb/cgdb_utils.h>

#include <cgsm/cg_storage_instance.h>

static uint64_t fs_id = 0;
static uint64_t instance_id = 0;

static uint64_t inode_number = 0;
static uint64_t root_inode_number = 0;
static uint64_t removed_inode_number = 0;

static cgdb_entry entry;

static cgdb_inode root_inode;

#define TEST_DB_ENTRY_NAME "entry"
#define TEST_DB_ENTRY_NAME_AFTER_RENAME "entryrenamed"

#define TEST_DB_ID_IN_INSTANCE "TestIDInInstance"

static int test_db_init(void)
{
    int result = cg_tests_init_all();

    TEST_ASSERT(result == 0, "cgutils_init_all");

    return result;
}

static int test_db_get_version(cgdb_data * const db)
{
    char * version = NULL;

    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_sync_get_version(db,
                                       &version);

    TEST_ASSERT(result == 0, "cgdb_sync_get_version");

    if (result == 0)
    {
        TEST_ASSERT(version != NULL, "cgdb_sync_get_version returned value");
        CGUTILS_FREE(version);
    }

    return result;
}

static int test_db_get_instance_id(cgdb_data * const db)
{
    uint64_t id = 0;

    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_sync_get_instance_id(db,
                                           "AquaRayCloudInstance1",
                                           &id);

    TEST_ASSERT(result == 0, "cgdb_sync_get_instance_id AquaRayCloudInstance1");

    if (result == 0)
    {
        TEST_ASSERT(id > 0, "cgdb_sync_get_instance_id AquaRayCloudInstance1 returned value");
        instance_id = id;
    }

    return result;
}

static int test_db_get_filesystem_id(cgdb_data * const db)
{
    uint64_t id = 0;

    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_sync_get_filesystem_id(db,
                                             "AutomatedTestsFS",
                                             &id);

    TEST_ASSERT(result == 0, "cgdb_sync_get_filesystem_id 0xDEAD");

    if (result == 0)
    {
        TEST_ASSERT(id > 0, "cgdb_sync_get_filesystem_id 0xDEAD returned value");
        fs_id = id;
    }

    return result;
}

static int test_db_clear_inodes_dirty_writers_cb(int const status,
                                                 void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_clear_inodes_dirty_writers_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_clear_inodes_dirty_writers_cb cb_data");

    return status;
}

static int test_db_clear_inodes_dirty_writers(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_clear_inodes_dirty_writers(db,
                                                 &test_db_clear_inodes_dirty_writers_cb,
                                                 db);

    TEST_ASSERT(result == 0, "cgdb_clear_inodes_dirty_writers");

    return result;
}

static int test_db_clear_inodes_instances_flags_cb(int const status,
                                                   void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_clear_inodes_instances_flags_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_clear_inodes_instances_flags_cb cb_data");

    return status;
}

static int test_db_clear_inodes_instances_flags(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_clear_inodes_instances_flags(db,
                                                   &test_db_clear_inodes_instances_flags_cb,
                                                   db);

    TEST_ASSERT(result == 0, "cgdb_sync_get_filesystem_id 0xDEAD");

    return result;
}

static int test_db_add_inode_instance_cb(int const status,
                                         void * const cb_data)
{
    TEST_ASSERT(status == 0, "cgdb_add_inode_instance result");
    TEST_ASSERT(cb_data != NULL, "cgdb_add_inode_instance cb");

    return status;
}

static int test_db_add_inode_instance(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_add_inode_instance(db,
                                         fs_id,
                                         instance_id,
                                         inode_number,
                                         TEST_DB_ID_IN_INSTANCE,
                                         /* status of 0: cg_storage_instance_status_ok */
                                         cg_storage_instance_status_ok,
                                         &test_db_add_inode_instance_cb,
                                         db);

    TEST_ASSERT(result == 0, "cgdb_add_inode");

    return result;
}

static int test_db_add_entry_cb(int const status,
                                uint64_t const ino,
                                void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_add_entry_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_add_entry_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(ino > 0, "new inode number > 0");

        if (ino > 0)
        {
            inode_number = ino;
            entry.inode.inode_number = ino;
        }
    }

    return status;
}

static int test_db_add_entry(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    entry = (cgdb_entry) { 0 };

    entry.name = (char *) TEST_DB_ENTRY_NAME;
    entry.fs_id = fs_id;
    entry.type = CGDB_OBJECT_TYPE_FILE;
    entry.inode.st.st_nlink = 1;
    entry.inode.in_cache = true;
    entry.inode.st.st_mode = S_IFREG|0600;

    int result = cgdb_add_new_entry_and_inode(db,
                                              root_inode_number,
                                              &entry,
                                              &test_db_add_entry_cb,
                                              &entry);

    TEST_ASSERT(result == 0, "cgdb_add_new_entry_and_inode");

    return result;
}

static int test_db_remove_inode_instance_cb(int const status,
                                            void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_remove_inode_instance_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_remove_inode_instance_cb cb_data");

    return status;
}

static int test_db_remove_inode_instance(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_remove_inode_instance(db,
                                            fs_id,
                                            instance_id,
                                            inode_number,
                                            TEST_DB_ID_IN_INSTANCE,
                                            /* Status dirty, just been dirtied previously */
                                            cg_storage_instance_status_dirty,
                                            &test_db_remove_inode_instance_cb,
                                            db);

    TEST_ASSERT(result == 0, "cgdb_remove_inode_instance");

    return result;
}

static int test_db_remove_entry_cb(int const status,
                                   uint64_t const removed_ino,
                                   bool const ino_has_been_removed,
                                   void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_remove_entry_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_remove_entry_cb cb_data");
    TEST_ASSERT(ino_has_been_removed == true, "test_db_remove_entry_cb removed");
    TEST_ASSERT(removed_ino == inode_number, "test_db_remove_entry_cb removed ino");

    removed_inode_number = inode_number;
    inode_number = 0;

    return status;
}

static int test_db_remove_entry(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_remove_inode_entry(db,
                                         fs_id,
                                         root_inode_number,
                                         TEST_DB_ENTRY_NAME_AFTER_RENAME,
                                         &test_db_remove_entry_cb,
                                         db);

    TEST_ASSERT(result == 0, "cgdb_remove_entry");

    return result;
}

#if 0
static int test_db_add_delayed_expunge_entry_cb(int const status,
                                                void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_add_delayed_expunge_entry_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_add_delayed_expunge_entry_cb cb_data");

    if (status == 0)
    {
    }

    return status;
}

static int test_db_add_delayed_expunge_entry(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(removed_inode_number > 0);

    int result = cgdb_add_delayed_expunge_entry(db,
                                                fs_id,
                                                removed_inode_number,
                                                "/delayed_expunge_entry",
                                                /* delete after now - 1 */
                                                (uint64_t) time(NULL) - 1,
                                                /* deleted 2 seconds ago */
                                                (uint64_t) time(NULL) - 2,
                                                &test_db_add_delayed_expunge_entry_cb,
                                                &entry);

    TEST_ASSERT(result == 0, "cgdb_add_delayed_expunge_entry");

    return result;
}

static int test_db_remove_delayed_expunge_entry_cb(int const status,
                                                void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_remove_delayed_expunge_entry_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_remove_delayed_expunge_entry_cb cb_data");

    if (status == 0)
    {
        removed_inode_number = 0;
    }

    return status;
}

static int test_db_remove_delayed_expunge_entry(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(removed_inode_number > 0);

    int result = cgdb_remove_delayed_expunge_entry(db,
                                                   fs_id,
                                                   removed_inode_number,
                                                   &test_db_remove_delayed_expunge_entry_cb,
                                                   &entry);

    TEST_ASSERT(result == 0, "cgdb_remove_delayed_expunge_entry");

    return result;
}

static int test_db_get_expired_delayed_expunge_entries_cb(int const status,
                                                          cgutils_llist * entries,
                                                          void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_expired_delayed_expunge_entries_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_expired_delayed_expunge_entries_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(entries != NULL, "test_db_get_expired_delayed_expunge_entries_cb entries");
        TEST_ASSERT(cgutils_llist_get_count(entries) > 0, "test_db_get_expired_delayed_expunge_entries_cb entries count");

        if (entries != NULL &&
                    cgutils_llist_get_count(entries) > 0)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(entries);
                 elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_delayed_expunge_entry const * const delayed_entry = cgutils_llist_elt_get_object(elt);
                TEST_ASSERT(delayed_entry != NULL, "test_db_get_expired_delayed_expunge_entries_cb entry");
            }
        }
    }

    if (entries != NULL)
    {
        cgutils_llist_free(&entries, &cgdb_delayed_expunge_entry_delete);
    }

    return status;
}

static int test_db_get_expired_delayed_expunge_entries(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(removed_inode_number > 0);

    int result = cgdb_get_expired_delayed_expunge_entries(db,
                                                          fs_id,
                                                          &test_db_get_expired_delayed_expunge_entries_cb,
                                                          &entry);

    TEST_ASSERT(result == 0, "test_db_get_expired_delayed_expunge_entries");

    return result;
}

static int test_db_get_delayed_expunge_entries_cb(int const status,
                                                  cgutils_llist * entries,
                                                  void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_delayed_expunge_entries_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_delayed_expunge_entries_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(entries != NULL, "test_db_get_delayed_expunge_entries_cb entries");
        TEST_ASSERT(cgutils_llist_get_count(entries) > 0, "test_db_get_delayed_expunge_entries_cb entries count");

        if (entries != NULL &&
                    cgutils_llist_get_count(entries) > 0)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(entries);
                 elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_delayed_expunge_entry const * const delayed_entry = cgutils_llist_elt_get_object(elt);
                TEST_ASSERT(delayed_entry != NULL, "test_db_get_delayed_expunge_entries_cb entry");
            }
        }
    }

    if (entries != NULL)
    {
        cgutils_llist_free(&entries, &cgdb_delayed_expunge_entry_delete);
    }

    return status;
}

static int test_db_get_delayed_expunge_entries(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(removed_inode_number > 0);

    int result = cgdb_get_delayed_expunge_entries(db,
                                                  fs_id,
                                                  "/%",
                                                  0,
                                                  &test_db_get_delayed_expunge_entries_cb,
                                                  &entry);

    TEST_ASSERT(result == 0, "test_db_get_delayed_expunge_entries");

    return result;
}
#endif /* 0 */

static int test_db_get_root_inode_info_cb(int const status,
                                          cgdb_inode * got_inode,
                                          void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_root_inode_info_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_root_inode_info_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(got_inode != NULL, "test_db_get_root_inode_info_cb inode");
        CGUTILS_ASSERT(got_inode != NULL);

        if (got_inode != NULL)
        {
            root_inode_number = got_inode->inode_number;

            if (cb_data != NULL)
            {
                TEST_ASSERT(&root_inode_number == cb_data, "test_db_get_root_inode_info_cb cb_data inode number");
            }

            TEST_ASSERT(cg_storage_object_mode_to_type(got_inode->st.st_mode) == CGDB_OBJECT_TYPE_DIRECTORY, "test_db_get_root_inode_info_cb type");
        }
    }

    if (got_inode != NULL)
    {
        cgdb_inode_free(got_inode), got_inode = NULL;
    }

    return status;
}

static int test_db_get_root_inode_info(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    time_t const now = time(NULL);
    root_inode = (cgdb_inode) { 0 };
    root_inode.st.st_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    root_inode.st.st_nlink = 1;
    root_inode.st.st_atime = now;
    root_inode.st.st_ctime = now;
    root_inode.st.st_mtime = now;
    root_inode.last_usage = (uint64_t) now;
    root_inode.last_modification = (uint64_t) now;

    int result = cgdb_get_or_create_root_inode(db,
                                               fs_id,
                                               &root_inode,
                                               &test_db_get_root_inode_info_cb,
                                               &root_inode_number);

    TEST_ASSERT(result == 0, "test_db_get_root_inode_info");

    return result;
}

static int test_db_get_inode_info_cb(int const status,
                                     cgdb_inode * got_inode,
                                     void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_inode_info_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_inode_info_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(got_inode != NULL, "test_db_get_inode_info_cb inode");
        CGUTILS_ASSERT(got_inode != NULL);

        if (got_inode != NULL)
        {
            TEST_ASSERT(got_inode->inode_number == inode_number, "test_db_get_inode_info_cb inode number");

            if (cb_data != NULL)
            {
                TEST_ASSERT(got_inode->inode_number == *((uint64_t *) cb_data), "test_db_get_inode_info_cb cb_data inode number");
            }

            TEST_ASSERT(cg_storage_object_mode_to_type(got_inode->st.st_mode) == CGDB_OBJECT_TYPE_FILE, "test_db_get_inode_info_cb type");
        }
    }

    if (got_inode != NULL)
    {
        cgdb_inode_free(got_inode), got_inode = NULL;
    }

    return status;
}

static int test_db_get_inode_info(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_get_inode_info(db,
                                     fs_id,
                                     inode_number,
                                     &test_db_get_inode_info_cb,
                                     &inode_number);

    TEST_ASSERT(result == 0, "test_db_get_inode_info");

    return result;
}

static int test_db_get_child_inode_info_cb(int const status,
                                           cgdb_inode * got_inode,
                                           void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_child_inode_info_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_child_inode_info_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(got_inode != NULL, "test_db_get_child_inode_info_cb inode");
        CGUTILS_ASSERT(got_inode != NULL);

        if (got_inode != NULL)
        {
            TEST_ASSERT(got_inode->inode_number == inode_number, "test_db_get_child_inode_info_cb inode number");

            if (cb_data != NULL)
            {
                TEST_ASSERT(got_inode->inode_number == *((uint64_t *) cb_data), "test_db_get_child_inode_info_cb cb_data inode number");
            }

            TEST_ASSERT(cg_storage_object_mode_to_type(got_inode->st.st_mode) == CGDB_OBJECT_TYPE_FILE, "test_db_get_child_inode_info_cb type");
        }
    }

    if (got_inode != NULL)
    {
        cgdb_inode_free(got_inode), got_inode = NULL;
    }

    return status;
}

static int test_db_get_child_inode_info(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_get_child_inode_info(db,
                                           fs_id,
                                           root_inode_number,
                                           TEST_DB_ENTRY_NAME,
                                           &test_db_get_child_inode_info_cb,
                                           &inode_number);

    TEST_ASSERT(result == 0, "test_db_get_child_inode_info");

    return result;
}

static int test_db_get_inode_instances_cb(int const status,
                                          /* llist of cgdb_inode_instance * */
                                          cgutils_llist * inode_instances,
                                          void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_inode_instances_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_inode_instances_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(inode_instances != NULL, "test_db_get_inode_instances_cb inode_instances");
        TEST_ASSERT(cgutils_llist_get_count(inode_instances) > 0, "test_db_get_inode_instances_cb inode_instances count");

        if (inode_instances != NULL &&
                    cgutils_llist_get_count(inode_instances) > 0)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(inode_instances);
                 elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_inode_instance const * const instance = cgutils_llist_elt_get_object(elt);
                TEST_ASSERT(instance != NULL, "test_db_get_inode_instances_cb instance");
                CGUTILS_ASSERT(instance != NULL);

                if (instance != NULL)
                {
                    TEST_ASSERT(instance->fs_id == fs_id, "test_db_get_inode_instances_cb instance fs_id");
                    TEST_ASSERT(instance->inode_number == inode_number, "test_db_get_inode_instances_cb instance inode_number");
                    TEST_ASSERT(instance->instance_id == instance_id, "test_db_get_inode_instances_cb instance instance_id");
                    CGUTILS_ASSERT(instance->id_in_instance != NULL);

                    if (instance->id_in_instance != NULL)
                    {
                        TEST_ASSERT(strcmp(TEST_DB_ID_IN_INSTANCE, instance->id_in_instance) == 0, "test_db_get_inode_instances_cb instance id_in_instance");
                    }
                }
            }
        }
    }

    if (inode_instances != NULL)
    {
        cgutils_llist_free(&inode_instances, &cgdb_inode_instance_delete);
    }

    return status;
}

static int test_db_get_inode_instances(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(inode_number > 0);

    int result = cgdb_get_inode_instances(db,
                                          fs_id,
                                          inode_number,
                                          &test_db_get_inode_instances_cb,
                                          db);

    TEST_ASSERT(result == 0, "test_db_get_inode_instances");

    return result;
}

static int test_db_get_inode_valid_instances_cb(int const status,
                                                /* llist of cgdb_inode_instance * */
                                                cgutils_llist * inode_instances,
                                                void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_inode_instances_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_inode_instances_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(inode_instances != NULL, "test_db_get_inode_instances_cb inode_instances");
        TEST_ASSERT(cgutils_llist_get_count(inode_instances) > 0, "test_db_get_inode_instances_cb inode_instances count");

        if (inode_instances != NULL &&
                    cgutils_llist_get_count(inode_instances) > 0)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(inode_instances);
                 elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_inode_instance const * const instance = cgutils_llist_elt_get_object(elt);
                TEST_ASSERT(instance != NULL, "test_db_get_inode_instances_cb instance");
                CGUTILS_ASSERT(instance != NULL);

                if (instance != NULL)
                {
                    TEST_ASSERT(instance->fs_id == fs_id, "test_db_get_inode_instances_cb instance fs_id");
                    TEST_ASSERT(instance->inode_number == inode_number, "test_db_get_inode_instances_cb instance inode_number");
                    TEST_ASSERT(instance->instance_id == instance_id, "test_db_get_inode_instances_cb instance instance_id");
                    CGUTILS_ASSERT(instance->id_in_instance != NULL);

                    if (instance->id_in_instance != NULL)
                    {
                        TEST_ASSERT(strcmp(TEST_DB_ID_IN_INSTANCE, instance->id_in_instance) == 0, "test_db_get_inode_instances_cb instance id_in_instance");
                    }

                    TEST_ASSERT(instance->status != cg_storage_instance_status_dirty, "test_db_get_inode_instances_cb instance status");
                }
            }
        }
    }

    if (inode_instances != NULL)
    {
        cgutils_llist_free(&inode_instances, &cgdb_inode_instance_delete);
    }

    return status;
}

static int test_db_get_inode_valid_instances(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(inode_number > 0);

    int result = cgdb_get_inode_valid_instances(db,
                                                fs_id,
                                                inode_number,
                                                /* not equal to cg_storage_instance_status_dirty */
                                                cg_storage_instance_status_dirty,
                                                &test_db_get_inode_valid_instances_cb,
                                                db);

    TEST_ASSERT(result == 0, "test_db_get_inode_valid_instances");

    return result;
}

static int test_db_get_directory_entries_cb(int const status,
                                            size_t const entries_count,
                                            /* vector of cgdb_entry * */
                                            cgutils_vector * entries,
                                            void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_directory_entries_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_directory_entries_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(entries_count > 0, "test_db_get_directory_entries_cb entries count > 0");

        if (entries_count > 0)
        {
            TEST_ASSERT(entries != NULL, "test_db_get_directory_entries_cb entries");
            TEST_ASSERT(cgutils_vector_count(entries) == entries_count, "test_db_get_directory_entries_cb entries count");

            if (entries != NULL &&
                cgutils_vector_count(entries) > 0)
            {
                for (size_t idx = 0;
                     idx < entries_count ;
                     idx++)
                {
                    cgdb_entry const * loop_entry = NULL;

                    int res = cgutils_vector_get(entries,
                                                 idx,
                                                 (void **) &loop_entry);

                    TEST_ASSERT(res == 0, "cgutils_vector_get");

                    if (res == 0)
                    {
                        TEST_ASSERT(loop_entry != NULL, "test_db_get_directory_entries_cb entry");
                        CGUTILS_ASSERT(loop_entry);

                        if (loop_entry != NULL)
                        {
                            TEST_ASSERT(loop_entry->name != NULL, "test_db_get_directory_entries_cb entry name");

                            if (loop_entry->name != NULL)
                            {
                                if (strcmp(loop_entry->name, "..") == 0 ||
                                    strcmp(loop_entry->name, ".") == 0)
                                {
                                    TEST_ASSERT(loop_entry->inode.inode_number == root_inode_number, "test_db_get_directory_entries_cb entry inode number");
                                }
                                else
                                {
                                    TEST_ASSERT(loop_entry->entry_id > 0, "test_db_get_directory_entries_cb entry entry id");
                                    TEST_ASSERT(loop_entry->inode.inode_number > 0, "test_db_get_directory_entries_cb entry inode number");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (entries != NULL)
    {
        cgutils_vector_deep_free(&entries, &cgdb_entry_delete);
    }

    return status;
}

static int test_db_get_inode_entries(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(root_inode_number > 0);

    int result = cgdb_get_inode_entries(db,
                                        fs_id,
                                        root_inode_number,
                                        &test_db_get_directory_entries_cb,
                                        db);

    TEST_ASSERT(result == 0, "test_db_get_inode_entries");

    return result;
}

static int test_db_count_inode_instances_by_status_cb(int const status,
                                                      size_t const count,
                                                      void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_count_inode_instances_by_status_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_count_inode_instances_by_status_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(count >= 1, "test_db_count_inode_instances_by_status_cb count");
    }

    return status;
}

static int test_db_count_inode_instances_by_status(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(inode_number > 0);

    int result = cgdb_count_inode_instances_by_status(db,
                                                      fs_id,
                                                      inode_number,
                                                      cg_storage_instance_status_ok,
                                                      &test_db_count_inode_instances_by_status_cb,
                                                      db);

    TEST_ASSERT(result == 0, "test_db_count_inode_instances_by_status");

    return result;
}

static int test_db_get_inode_instances_by_status_cb(int const status,
                                                    /* llist of cgdb_inode_instance * */
                                                    cgutils_llist * inode_instances,
                                                    void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_inode_instances_by_status_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_inode_instances_by_status_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(inode_instances != NULL, "test_db_get_inode_instances_by_status_cb inode_instances");
        TEST_ASSERT(cgutils_llist_get_count(inode_instances) > 0, "test_db_get_inode_instances_by_status_cb inode_instances count");

        if (inode_instances != NULL &&
                    cgutils_llist_get_count(inode_instances) > 0)
        {
            for (cgutils_llist_elt * elt = cgutils_llist_get_first(inode_instances);
                 elt != NULL;
                 elt = cgutils_llist_elt_get_next(elt))
            {
                cgdb_inode_instance const * const instance = cgutils_llist_elt_get_object(elt);
                TEST_ASSERT(instance != NULL, "test_db_get_inode_instances_by_status_cb instance");
                CGUTILS_ASSERT(instance != NULL);

                if (instance != NULL)
                {
                    TEST_ASSERT(instance->fs_id > 0, "test_db_get_inode_instances_by_status_cb instance fs_id");
                    TEST_ASSERT(instance->inode_number > 0, "test_db_get_inode_instances_by_status_cb instance inode_number");
                    TEST_ASSERT(instance->instance_id > 0, "test_db_get_inode_instances_by_status_cb instance instance_id");
                    TEST_ASSERT(instance->id_in_instance != NULL, "test_db_get_inode_instances_by_status_cb instance id_in_instance");
                    TEST_ASSERT(instance->status == cg_storage_instance_status_ok, "test_db_get_inode_instances_by_status_cb instance status");
                }
            }
        }
    }

    if (inode_instances != NULL)
    {
        cgutils_llist_free(&inode_instances, &cgdb_inode_instance_delete);
    }

    return status;
}

static int test_db_get_inode_instances_by_status(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);

    int result = cgdb_get_inode_instances_by_status(db,
                                                    cg_storage_instance_status_ok,
                                                    (cgdb_limit_type) 50,
                                                    (cgdb_skip_type) 0,
                                                    &test_db_get_inode_instances_by_status_cb,
                                                    db);

    TEST_ASSERT(result == 0, "test_db_get_inode_instances_by_status");

    return result;
}

static int test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb(int const status,
                                                                           size_t const entries_count,
                                                                           /* vector of cgdb_entry * */
                                                                           cgutils_vector * entries,
                                                                           void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb cb_data");

    if (status == 0)
    {
        TEST_ASSERT(entries_count > 0, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entries_count");

        if (entries_count > 0)
        {
            TEST_ASSERT(entries != NULL, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entries");
            TEST_ASSERT(cgutils_vector_count(entries) == entries_count, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entries count");

            if (entries != NULL)
            {
                for (size_t idx = 0 ;
                     idx < entries_count;
                     idx++)
                {
                    cgdb_entry const * loop_entry = NULL;

                    int res = cgutils_vector_get(entries,
                                                 idx,
                                                 (void **) &loop_entry);

                    TEST_ASSERT(res == 0, "cgutils_vector_get");

                    if (res == 0)
                    {
                        TEST_ASSERT(loop_entry != NULL, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry");
                        CGUTILS_ASSERT(loop_entry);

                        if (loop_entry != NULL)
                        {
                            TEST_ASSERT(loop_entry->name != NULL, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry name");
                            TEST_ASSERT(loop_entry->entry_id > 0, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry id");
                            TEST_ASSERT(loop_entry->fs_id == fs_id, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry fs_id");

                            TEST_ASSERT(loop_entry->type == CGDB_OBJECT_TYPE_FILE, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry fs_id");
                            TEST_ASSERT(loop_entry->inode.inode_number > 0, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry inode number");
                            TEST_ASSERT(loop_entry->inode.in_cache == true, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb entry inode in_cache");
                        }
                    }
                }
            }
        }
    }

    if (entries != NULL)
    {
        cgutils_vector_deep_free(&entries, &cgdb_entry_delete);
    }

    return status;
}

static int test_db_get_not_dirty_entries_by_type_size_last_usage_cached(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);

    int result = cgdb_get_not_dirty_entries_by_type_size_last_usage_cached(db,
                                                                           fs_id,
                                                                           CGDB_OBJECT_TYPE_FILE,
                                                                           0,
                                                                           0,
                                                                           cg_storage_instance_status_dirty,
                                                                           50,
                                                                           0,
                                                                           &test_db_get_not_dirty_entries_by_type_size_last_usage_cached_cb,
                                                                           db);

    TEST_ASSERT(result == 0, "test_db_get_not_dirty_entries_by_type_size_last_usage_cached");

    return result;
}

static int test_db_rename_cb(int const status,
                             uint64_t const renamed_ino,
                             uint64_t const removed_ino,
                             bool const has_ino_been_removed,
                             void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_rename_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_rename_cb cb_data");
    TEST_ASSERT(renamed_ino == inode_number, "test_db_rename_cb renamed inode number");
    TEST_ASSERT(removed_ino == 0, "test_db_rename_cb no previous ino");
    TEST_ASSERT(has_ino_been_removed == false, "test_db_rename_cb no previous ino");


    if (status == 0)
    {
    }

    return status;
}

static int test_db_rename(cgdb_data * const db)
{
    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);

    int result = cgdb_rename_inode(db,
                                   fs_id,
                                   root_inode_number,
                                   TEST_DB_ENTRY_NAME,
                                   root_inode_number,
                                   TEST_DB_ENTRY_NAME_AFTER_RENAME,
                                   &test_db_rename_cb,
                                   &entry);

    TEST_ASSERT(result == 0, "cgdb_rename");

    return result;
}

static int test_db_generic_status_cb(int const status,
                                     void * const cb_data)
{
    TEST_ASSERT(status == 0, "test_db_generic_status_cb status");
    TEST_ASSERT(cb_data != NULL, "test_db_generic_status_cb cb_data");

    if (status != 0 &&
        cb_data != NULL)
    {
        char const * const str = cb_data;

        LOG("%s test failed with %d",
            str,
            status);
    }

    return status;
}

static int test_db_update_inode_digest(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_digest";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(inode_number > 0);

    int result = cgdb_update_inode_digest(db,
                                          fs_id,
                                          inode_number,
                                          cgutils_crypto_digest_algorithm_none,
                                          "a",
                                          1,
                                          (uint64_t) time(NULL),
                                          &test_db_generic_status_cb,
                                          (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_digest");

    return result;
}

static int test_db_update_inode_cache_status(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_cache_status";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(inode_number > 0);

    int result = cgdb_update_inode_cache_status(db,
                                                fs_id,
                                                inode_number,
                                                true,
                                                &test_db_generic_status_cb,
                                                (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_cache_status");

    return result;
}

static int test_db_update_inode_counter(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_counter";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(inode_number > 0);

    int result = cgdb_update_inode_counter(db,
                                           fs_id,
                                           inode_number,
                                           0,
                                           true,
                                           &test_db_generic_status_cb,
                                           (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_counter");

    return result;
}

static int test_db_update_inode_instance_set_uploading(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_instance_set_uploading";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(instance_id > 0);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(TEST_DB_ID_IN_INSTANCE != NULL);

    int result = cgdb_update_inode_instance_set_uploading(db,
                                                          fs_id,
                                                          instance_id,
                                                          inode_number,
                                                          TEST_DB_ID_IN_INSTANCE,
                                                          &test_db_generic_status_cb,
                                                          (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_instance_set_uploading");

    return result;
}

static int test_db_update_inode_instance_set_uploading_done(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_instance_set_uploading_done";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(instance_id > 0);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(TEST_DB_ID_IN_INSTANCE != NULL);

    int result = cgdb_update_inode_instance_set_uploading_done(db,
                                                               fs_id,
                                                               instance_id,
                                                               inode_number,
                                                               TEST_DB_ID_IN_INSTANCE,
                                                               false,
                                                               &test_db_generic_status_cb,
                                                               (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_instance_set_uploading_done");

    return result;
}

static int test_db_update_inode_instance_clear_dirty_status(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_instance_clear_dirty_status";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(instance_id > 0);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(TEST_DB_ID_IN_INSTANCE != NULL);

    int result = cgdb_update_inode_instance_clear_dirty_status(db,
                                                               fs_id,
                                                               instance_id,
                                                               inode_number,
                                                               TEST_DB_ID_IN_INSTANCE,
                                                               cg_storage_instance_status_dirty,
                                                               cg_storage_instance_status_ok,
                                                               false,
                                                               false,
                                                               &test_db_generic_status_cb,
                                                               (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_instance_clear_dirty_status");

    return result;
}

static int test_db_update_inode_instance_set_delete_in_progress(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_instance_set_delete_in_progress";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(instance_id > 0);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(TEST_DB_ID_IN_INSTANCE != NULL);

    int result = cgdb_update_inode_instance_set_delete_in_progress(db,
                                                                   fs_id,
                                                                   instance_id,
                                                                   inode_number,
                                                                   TEST_DB_ID_IN_INSTANCE,
                                                                   &test_db_generic_status_cb,
                                                                   (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_instance_set_delete_in_progress");

    return result;
}

static int test_db_update_inode_instance_set_deleting_failed(cgdb_data * const db)
{
    static char const str[] = "cgdb_update_inode_instance_set_deleting_failed";

    CGUTILS_ASSERT(db != NULL);
    CGUTILS_ASSERT(fs_id > 0);
    CGUTILS_ASSERT(instance_id > 0);
    CGUTILS_ASSERT(inode_number > 0);
    CGUTILS_ASSERT(TEST_DB_ID_IN_INSTANCE != NULL);

    int result = cgdb_update_inode_instance_set_deleting_failed(db,
                                                                fs_id,
                                                                instance_id,
                                                                inode_number,
                                                                TEST_DB_ID_IN_INSTANCE,
                                                                &test_db_generic_status_cb,
                                                                (void *) str);

    TEST_ASSERT(result == 0, "cgdb_update_inode_instance_set_deleting_failed");

    return result;
}

int main(void)
{
    int result = test_db_init();

    if (result == 0)
    {
        cgutils_event_data * event_data = NULL;

        result = cgutils_event_init(&event_data);
        TEST_ASSERT(result == 0, "event init");

        if (result == 0)
        {
            static struct
            {
                char const * const backend_name;
                char const * const backend_file;
            } const db_backends[] =
                  {
                      { "PG", CONFIG_FILE_PG },
                  };

            static size_t const db_backends_count = sizeof db_backends / sizeof *db_backends;

            for (size_t idx = 0; idx < db_backends_count; idx++)
            {
                cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_DIM, CLOUDUTILS_ANSI_COLOR_CYAN, CLOUDUTILS_ANSI_COLOR_BLACK);
                CGUTILS_DEBUG("Testing backend %s", db_backends[idx].backend_name);
                cgutils_set_color(stderr, CLOUDUTILS_ANSI_COLOR_ATTR_RESET, CLOUDUTILS_ANSI_COLOR_WHITE, CLOUDUTILS_ANSI_COLOR_BLACK);

                cgutils_configuration * cg_conf = NULL;
                result = cgutils_configuration_from_xml_file(db_backends[idx].backend_file,
                                                             &cg_conf);

                TEST_ASSERT(result == 0, "cgutils_configuration_from_xml_file");

                if (result == 0)
                {
                    char * backends_path = NULL;

                    result = cgutils_configuration_get_string(cg_conf,
                                                              "General/DBBackendsPath",
                                                              &backends_path);

                    TEST_ASSERT(result == 0, "cgutils_configuration_get_string");

                    if (result == 0)
                    {
                        cgutils_configuration * db_conf = NULL;

                        result = cgutils_configuration_from_path(cg_conf,
                                                                 "DB",
                                                                 &db_conf);

                        TEST_ASSERT(result == 0, "cgutils_configuration_from_path");

                        if (result == 0)
                        {
                            cgdb_data * db = NULL;

                            result = cgdb_data_init(backends_path,
                                                    db_conf,
                                                    event_data,
                                                    &db);

                            TEST_ASSERT(result == 0, "cgdb_data_init");

                            if (result == 0)
                            {
                                static struct
                                {
                                    char const * const name;
                                    int (*cb)(cgdb_data *);
                                }
                                const tests[] =
                                    {
#define TEST(cb) { #cb, &cb } ,
                                        TEST(test_db_get_version)
                                        TEST(test_db_get_instance_id)
                                        TEST(test_db_get_filesystem_id)

                                        TEST(test_db_clear_inodes_dirty_writers)
                                        TEST(test_db_clear_inodes_instances_flags)

                                        TEST(test_db_get_root_inode_info)
                                        TEST(test_db_add_entry)
                                        TEST(test_db_add_inode_instance)

                                        TEST(test_db_get_inode_info)
                                        TEST(test_db_get_child_inode_info)

                                        TEST(test_db_get_inode_instances)
                                        TEST(test_db_get_inode_valid_instances)

                                        TEST(test_db_get_inode_entries)

                                        TEST(test_db_count_inode_instances_by_status)
                                        TEST(test_db_get_inode_instances_by_status)

                                        TEST(test_db_get_not_dirty_entries_by_type_size_last_usage_cached)

                                        TEST(test_db_rename)

                                        TEST(test_db_update_inode_digest)
                                        TEST(test_db_update_inode_cache_status)
                                        TEST(test_db_update_inode_counter)

                                        TEST(test_db_update_inode_instance_set_uploading)
                                        TEST(test_db_update_inode_instance_set_uploading_done)
                                        TEST(test_db_update_inode_instance_clear_dirty_status)
                                        TEST(test_db_update_inode_instance_set_delete_in_progress)
                                        TEST(test_db_update_inode_instance_set_deleting_failed)

                                        TEST(test_db_remove_inode_instance)
                                        TEST(test_db_remove_entry)

#if 0
                                        TEST(test_db_add_delayed_expunge_entry)
                                        TEST(test_db_get_expired_delayed_expunge_entries)
                                        TEST(test_db_get_delayed_expunge_entries)
                                        TEST(test_db_remove_delayed_expunge_entry)
#endif /* 0 */

#undef TEST
                                    };
                                static size_t const tests_count = sizeof tests / sizeof *tests;

                                for (size_t tests_idx = 0;
                                     result == 0 &&
                                         tests_idx < tests_count;
                                     tests_idx++)
                                {
                                    result = (*(tests[tests_idx].cb))(db);

                                    TEST_ASSERT(result == 0, tests[tests_idx].name);

                                    if (result == 0)
                                    {
                                        cgutils_event_dispatch(event_data);
                                    }
                                }

                                cgdb_data_free(db), db = NULL;
                            }

                            cgutils_configuration_free(db_conf), db_conf = NULL;
                        }

                        CGUTILS_FREE(backends_path);
                    }

                    cgutils_configuration_free(cg_conf), cg_conf = NULL;
                }
            }

            cgutils_event_destroy(event_data);
        }

        cg_tests_destroy_all();
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}
