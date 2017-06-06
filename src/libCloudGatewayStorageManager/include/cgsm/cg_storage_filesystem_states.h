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
STATE(none)
STATE(fetching_entry)
STATE(fetching_dir_entries)
STATE(inserting_entry)
STATE(removing_entry)
STATE(setting_upload_in_progress)
STATE(uploading_inode)
STATE(setting_upload_done)
STATE(dirty_status_cleared)
STATE(handling_error)
STATE(setting_delete_in_progress)
STATE(deleting_inode)
STATE(deleting_inode_from_db)
STATE(updating_cache_status)
STATE(updating_cache_status_after_retrieval)
STATE(fetching_inode_instances)
STATE(retrieving_inode)
STATE(updating_dirty_writers)
STATE(setting_dirty)
STATE(releasing)
STATE(adding_inode_instances)
STATE(inode_digest_updated)
STATE(renaming_entry)
STATE(adding_delayed_expunge_entry)
STATE(queued)
STATE(retrieving_data)
STATE(rolling_back_dirty_writers_after_error)
STATE(updating_inode_attributes)
