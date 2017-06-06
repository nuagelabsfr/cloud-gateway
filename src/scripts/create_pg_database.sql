-- SET client_min_messages='warning';

CREATE TABLE IF NOT EXISTS filesystems(
    fs_id BIGSERIAL NOT NULL UNIQUE,
    fs_name TEXT NOT NULL UNIQUE,
    PRIMARY KEY(fs_id)
    );

CREATE TABLE IF NOT EXISTS instances(
    instance_id BIGSERIAL NOT NULL UNIQUE,
    instance_name TEXT NOT NULL UNIQUE,
    PRIMARY KEY(instance_id)
    );

CREATE TABLE IF NOT EXISTS inodes(
    inode_number BIGSERIAL NOT NULL UNIQUE,
    fs_id BIGINT NOT NULL REFERENCES filesystems(fs_id),
    uid BIGINT NOT NULL,
    gid BIGINT NOT NULL,
    mode BIGINT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    atime BIGINT NOT NULL,
    ctime BIGINT NOT NULL,
    mtime BIGINT NOT NULL,
    last_usage BIGINT NOT NULL,
    last_modification BIGINT NOT NULL,
    nlink BIGINT NOT NULL CHECK (nlink >= 0),
    dirty_writers BIGINT NOT NULL CHECK (dirty_writers >= 0),
    in_cache BOOLEAN NOT NULL,
    digest_type SMALLINT,
    digest TEXT NOT NULL,
    PRIMARY KEY(inode_number, fs_id)
    );

CREATE TABLE IF NOT EXISTS entries(
    entry_id BIGSERIAL NOT NULL UNIQUE,
    fs_id BIGINT NOT NULL REFERENCES filesystems(fs_id),
    parent_entry_id BIGINT REFERENCES entries(entry_id),
    inode_number BIGINT NOT NULL REFERENCES inodes(inode_number) ON DELETE CASCADE,
    type SMALLINT NOT NULL,
    name TEXT NOT NULL,
    link_to TEXT,
    PRIMARY KEY(entry_id, fs_id),
    UNIQUE(parent_entry_id, name)
    );

CREATE INDEX entries_inode_number_idx ON entries USING btree (inode_number);
CREATE INDEX entries_parent_idx ON entries USING btree (parent_entry_id);
CREATE INDEX entries_type_idx ON entries USING btree (type);

CREATE TABLE IF NOT EXISTS inodes_instances(
    inode_instance_id BIGSERIAL NOT NULL UNIQUE,
    instance_id BIGINT NOT NULL REFERENCES instances(instance_id),
    upload_time BIGINT NOT NULL,
    delete_after_time BIGINT,
    status SMALLINT NOT NULL,
    uploading BOOLEAN NOT NULL,
    deleting BOOLEAN NOT NULL,
    id_in_instance TEXT NOT NULL,
    upload_failures BIGINT,
    download_failures BIGINT,
    last_upload_failure BIGINT,
    last_download_failure BIGINT,
    digest_type SMALLINT,
    digest TEXT,
    compressed BOOLEAN,
    compression_type SMALLINT,
    encrypted BOOLEAN,
    encryption_type SMALLINT,
    PRIMARY KEY(inode_instance_id)
    );

CREATE INDEX inodes_instances_status_idx ON inodes_instances USING btree (status);
CREATE INDEX inodes_instances_id_in_instance_idx ON inodes_instances USING btree (id_in_instance);

CREATE TABLE IF NOT EXISTS inodes_instances_link(
    fs_id BIGINT NOT NULL REFERENCES filesystems(fs_id),
    inode_number BIGINT,
    inode_instance_id BIGINT NOT NULL REFERENCES inodes_instances(inode_instance_id),
    PRIMARY KEY(fs_id, inode_number, inode_instance_id)
    );

CREATE INDEX inodes_instances_link_inode_instance_id_idx ON inodes_instances_link USING btree (inode_instance_id);

CREATE TABLE IF NOT EXISTS delayed_expunge_entries(
    fs_id BIGINT NOT NULL REFERENCES filesystems(fs_id),
    inode_number BIGINT,
    full_path TEXT NOT NULL,
    delete_after BIGINT NOT NULL,
    deletion_time BIGINT NOT NULL,
    PRIMARY KEY(fs_id, inode_number)
    );

CREATE INDEX delayed_expunge_entries_full_path_idx ON delayed_expunge_entries USING btree (full_path);

CREATE OR REPLACE FUNCTION get_filesystem_id(name TEXT)
RETURNS BIGINT AS $$
DECLARE
    id BIGINT;
BEGIN
    LOCK TABLE filesystems IN SHARE ROW EXCLUSIVE MODE;

    BEGIN
        SELECT fs_id INTO STRICT id
        FROM filesystems
        WHERE fs_name = name;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO filesystems(fs_name)
            VALUES (name)
            RETURNING fs_id INTO STRICT id;
        WHEN TOO_MANY_ROWS THEN
            RAISE EXCEPTION 'Filesystem % is not unique', name;
    END;

    RETURN id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_instance_id(name TEXT)
RETURNS BIGINT AS $$
DECLARE
    id BIGINT;
BEGIN
    LOCK TABLE instances IN SHARE ROW EXCLUSIVE MODE;
    BEGIN
        SELECT instance_id INTO STRICT id
        FROM instances
        WHERE instance_name = name;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO instances(instance_name)
            VALUES (name)
            RETURNING instance_id INTO STRICT id;
        WHEN TOO_MANY_ROWS THEN
            RAISE EXCEPTION 'Instance % is not unique', name;
    END;

    RETURN id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION decrement_inode_usage(inode_num_p BIGINT, fs_id_p BIGINT, ctime_p BIGINT)
RETURNS BIGINT AS $$
DECLARE
    nlink_var BIGINT;
BEGIN

    BEGIN
        PERFORM inode_number
        FROM inodes
        WHERE inode_number = inode_num_p
        AND fs_id = fs_id_p
        FOR UPDATE;

        UPDATE inodes AS ino
        SET nlink = ino.nlink - 1, ctime = ctime_p
        WHERE inode_number = inode_num_p
        AND fs_id = fs_id_p
        RETURNING ino.nlink INTO STRICT nlink_var;

        IF nlink_var = 0 THEN
           DELETE FROM inodes
           WHERE inode_number = inode_num_p
           AND fs_id = fs_id_p;

           UPDATE inodes_instances AS ii
           SET status = 2
           FROM inodes_instances_link AS iil
           WHERE iil.inode_instance_id = ii.inode_instance_id
           AND iil.inode_number = inode_num_p
           AND iil.fs_id = fs_id_p;

        END IF;
    EXCEPTION
        WHEN TOO_MANY_ROWS THEN
            RAISE EXCEPTION 'Inode % in fs % is not unique', inode_num_p, fs_id_p;
    END;

    RETURN nlink_var;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION remove_delayed_expunge_entry(fs_id_p BIGINT, inode_num_p BIGINT)
RETURNS void AS $$
DECLARE
    ctime_var BIGINT;
BEGIN

    BEGIN
        PERFORM ent.inode_number
        FROM delayed_expunge_entries AS ent
        WHERE ent.inode_number = inode_num_p
        AND fs_id = fs_id_p;

        IF FOUND THEN
            DELETE FROM delayed_expunge_entries
            WHERE fs_id = fs_id_p
            AND inode_number = inode_num_p;

            SELECT extract(epoch from now())::bigint
            INTO STRICT ctime_var;

            PERFORM decrement_inode_usage(inode_num_p, fs_id_p, ctime_var);
        ELSE
            RAISE EXCEPTION 'Not delayed entry found for inode % of fs %s', inode_num_p, fs_id_p;
        END IF;

    EXCEPTION
        WHEN TOO_MANY_ROWS THEN
            RAISE EXCEPTION 'Inode % in fs % is not unique', inode_num_p, fs_id_p;
    END;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION remove_inode_instance_and_link(fs_id_p BIGINT, instance_id_p BIGINT, inode_number_p BIGINT, id_in_instance_p TEXT, status_p SMALLINT)
RETURNS void AS $$
BEGIN

    BEGIN

        DELETE FROM inodes_instances_link AS iil
        USING inodes_instances AS ii
        WHERE ii.inode_instance_id = iil.inode_instance_id
        AND ii.instance_id = instance_id_p
        AND ii.id_in_instance = id_in_instance_p
        AND ii.status = status_p
        AND fs_id = fs_id_p
        AND inode_number = inode_number_p;

        DELETE FROM inodes_instances AS ii
        WHERE ii.instance_id = instance_id_p
        AND ii.id_in_instance = id_in_instance_p
        AND ii.status = status_p;

    END;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION add_inode_instance_and_link(fs_id_p BIGINT, instance_id_p BIGINT, inode_number_p BIGINT, id_in_instance_p TEXT,
        status_p SMALLINT, upload_time_p BIGINT, uploading_p BOOLEAN, deleting_p BOOLEAN)
RETURNS void AS $$
DECLARE
    inode_instance_id_var BIGINT;
BEGIN

    BEGIN

        INSERT INTO inodes_instances(instance_id, id_in_instance, status, upload_time, uploading, deleting)
        VALUES (instance_id_p, id_in_instance_p, status_p, upload_time_p, uploading_p, deleting_p)
        RETURNING inode_instance_id INTO STRICT inode_instance_id_var;

        INSERT INTO inodes_instances_link(fs_id, inode_number, inode_instance_id)
        VALUES (fs_id_p, inode_number_p, inode_instance_id_var);
    END;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE TYPE entry_type AS (
    parent_entry_id BIGINT,
    entry_id BIGINT,
    fs_id BIGINT,
    type SMALLINT,
    name TEXT,
    link_to TEXT,
    inode_number BIGINT,
    uid BIGINT,
    gid BIGINT,
    mode BIGINT,
    size BIGINT,
    atime BIGINT,
    ctime BIGINT,
    mtime BIGINT,
    last_usage BIGINT,
    last_modification BIGINT,
    nlink BIGINT,
    dirty_writers BIGINT,
    in_cache BOOLEAN,
    digest TEXT,
    digest_type SMALLINT
);

CREATE OR REPLACE FUNCTION get_entry_from_path(fs_id_var BIGINT, path_var TEXT)
RETURNS SETOF entry_type AS $$
DECLARE
    entry_name_var TEXT;
    entry_id_var BIGINT;
    counter_var INT;
BEGIN
    entry_id_var := 0;
    counter_var := 2;
    SELECT entry_id INTO STRICT entry_id_var FROM entries WHERE fs_id = fs_id_var AND parent_entry_id IS NULL;
    <<innerloop>>
    LOOP
        BEGIN
            SELECT split_part(path_var, '/'::TEXT,  counter_var) INTO STRICT entry_name_var;
            IF entry_name_var = '' THEN

                RETURN QUERY SELECT ent.parent_entry_id, ent.entry_id AS entry_id, ent.fs_id AS fs_id, type, name, link_to, ino.inode_number AS inode_number, uid, gid, mode, size, atime, ctime, mtime, last_usage, last_modification, nlink, dirty_writers, in_cache, digest, digest_type
                FROM entries AS ent
                INNER JOIN inodes AS ino ON (ent.inode_number = ino.inode_number AND ent.fs_id = ino.fs_id)
                WHERE ent.fs_id = fs_id_var
                AND ent.entry_id = entry_id_var
                LIMIT 1;

                RETURN;
            END IF;
        END;
        BEGIN
            SELECT entry_id INTO STRICT entry_id_var
            FROM entries
            WHERE fs_id = fs_id_var
            AND parent_entry_id = entry_id_var
            AND name = entry_name_var;

            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    EXIT innerloop;
        END;
    counter_var := counter_var + 1;
    END LOOP;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_or_create_root_inode(fs_id_p BIGINT, uid_p BIGINT, gid_p BIGINT, mode_p BIGINT, size_p BIGINT, atime_p BIGINT, ctime_p BIGINT, mtime_p BIGINT, last_usage_p BIGINT, last_modification_p BIGINT, nlink_p BIGINT, dirty_writers_p BIGINT, in_cache_p BOOLEAN, digest_type_p SMALLINT, digest_p TEXT)
RETURNS TABLE(inode_number BIGINT, uid BIGINT, gid BIGINT, mode BIGINT, size BIGINT, atime BIGINT, ctime BIGINT, mtime BIGINT, last_usage BIGINT, last_modification BIGINT, nlink BIGINT, dirty_writers BIGINT, in_cache BOOLEAN, digest TEXT, digest_type SMALLINT) AS $$
DECLARE
    entry_id_var BIGINT;
    inode_number_var BIGINT;
BEGIN
    BEGIN
        LOCK TABLE entries IN SHARE ROW EXCLUSIVE MODE;

        SELECT ent.inode_number INTO inode_number_var
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND parent_entry_id is NULL
        AND ent.type = 2;

        IF NOT FOUND THEN
            INSERT INTO inodes(fs_id, uid, gid, mode, size, atime, ctime, mtime, last_usage, last_modification, nlink, dirty_writers, in_cache, digest_type, digest)
            VALUES(fs_id_p, uid_p, gid_p, mode_p, size_p, atime_p, ctime_p, mtime_p, last_usage_p, last_modification_p, nlink_p, dirty_writers_p, in_cache_p, digest_type_p, digest_p)
            RETURNING inodes.inode_number INTO STRICT inode_number_var;

            INSERT INTO entries(fs_id, inode_number, type, name, link_to, parent_entry_id)
            VALUES (fs_id_p, inode_number_var, 2, '', NULL, NULL)
            RETURNING entries.entry_id INTO STRICT entry_id_var;
        END IF;

        RETURN QUERY SELECT ino.inode_number, ino.uid, ino.gid, ino.mode, ino.size, ino.atime, ino.ctime, ino.mtime, ino.last_usage, ino.last_modification, ino.nlink, ino.dirty_writers, ino.in_cache, ino.digest, ino.digest_type
        FROM inodes AS ino
        WHERE ino.inode_number = inode_number_var
        AND ino.fs_id = fs_id_p;
        RETURN;
    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION add_low_inode_and_entry(fs_id_p BIGINT, parent_inode_number_p BIGINT, name_p TEXT, type_p SMALLINT, link_to_p TEXT, uid_p BIGINT, gid_p BIGINT, mode_p BIGINT, size_p BIGINT, atime_p BIGINT, ctime_p BIGINT, mtime_p BIGINT, last_usage_p BIGINT, last_modification_p BIGINT, nlink_p BIGINT, dirty_writers_p BIGINT, in_cache_p BOOLEAN, digest_type_p SMALLINT, digest_p TEXT)
RETURNS TABLE (return_code SMALLINT, inode_number BIGINT) AS $$
DECLARE
    parent_entry_id_var BIGINT;
    parent_entry_type_var SMALLINT;
    entry_id_var BIGINT;
    inode_number_var BIGINT;
BEGIN
    BEGIN
        LOCK TABLE entries IN SHARE ROW EXCLUSIVE MODE;

        -- get the parent
        SELECT ent.entry_id, ent.type INTO parent_entry_id_var, parent_entry_type_var
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND ent.inode_number = parent_inode_number_p;

        IF FOUND THEN
            -- check that the parent is a directory
            IF parent_entry_type_var = 2 THEN
                -- check whether there is an existing entry
                -- with the same parent and name
                SELECT entry_id INTO entry_id_var
                FROM entries AS ent
                WHERE ent.fs_id = fs_id_p
                AND ent.parent_entry_id = parent_entry_id_var
                AND ent.name = name_p;

                IF NOT FOUND THEN

                    -- insert inode (hardlinking is handled by an another DB function)
                    INSERT INTO inodes(fs_id, uid, gid, mode, size, atime, mtime, ctime, last_usage, last_modification, nlink, dirty_writers, in_cache, digest_type, digest)
                    VALUES (fs_id_p, uid_p, gid_p, mode_p, size_p, atime_p, mtime_p, ctime_p, last_usage_p, last_modification_p, nlink_p, dirty_writers_p, in_cache_p, digest_type_p, digest_p)
                    RETURNING inodes.inode_number INTO STRICT inode_number_var;

                    -- insert entry
                    INSERT INTO entries(fs_id, inode_number, type, name, link_to, parent_entry_id)
                    VALUES(fs_id_p, inode_number_var, type_p, name_p, link_to_p, parent_entry_id_var)
                    RETURNING entries.entry_id INTO STRICT entry_id_var;

                    -- update parent's inode mtime and ctime
                    UPDATE inodes AS ino
                    SET mtime = ctime_p, ctime = ctime_p
                    FROM entries AS ent
                    WHERE ent.fs_id = ino.fs_id
                    AND ent.inode_number = ino.inode_number
                    AND ino.fs_id = fs_id_p
                    AND ent.entry_id = parent_entry_id_var;

                    RETURN QUERY SELECT 0::SMALLINT AS return_code, inode_number_var AS inode_number;
                    RETURN;
                ELSE
                    -- return EEXIST
                    RETURN QUERY SELECT 17::SMALLINT AS return_code, 0::BIGINT AS inode_number;
                    RETURN;
                END IF;
            ELSE
                -- return ENOTDIR
                RETURN QUERY SELECT 20::SMALLINT AS return_code, 0::BIGINT AS inode_number;
                RETURN;
            END IF;
        ELSE
            -- return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS inode_number;
            RETURN;
        END IF;
    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION release_low_inode(fs_id_p BIGINT, inode_number_p BIGINT, mtime_p BIGINT, ctime_p BIGINT, last_modification_p BIGINT, size_p BIGINT, old_status_p SMALLINT, new_status_p SMALLINT)
RETURNS void AS $$
DECLARE

BEGIN
    BEGIN

        UPDATE inodes_instances AS ii
        SET status = new_status_p
        FROM inodes_instances_link AS iil
        WHERE iil.inode_instance_id = ii.inode_instance_id
        AND iil.fs_id = fs_id_p
        AND iil.inode_number = inode_number_p
        AND ii.status = old_status_p;

        UPDATE inodes AS ino
        SET size = size_p, ctime = ctime_p, mtime = mtime_p, last_modification = last_modification_p, dirty_writers = ino.dirty_writers - 1, digest = '', digest_type = 0
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = inode_number_p
        AND ino.dirty_writers > 0;

    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION set_inode_and_all_inodes_instances_dirty(fs_id_p BIGINT, inode_number_p BIGINT, mtime_p BIGINT, ctime_p BIGINT, last_modification_p BIGINT, old_status_p SMALLINT, new_status_p SMALLINT)
RETURNS void AS $$
DECLARE
BEGIN
    BEGIN

        UPDATE inodes_instances AS ii
        SET status = new_status_p
        FROM inodes_instances_link AS iil
        WHERE iil.inode_instance_id = ii.inode_instance_id
        AND iil.fs_id = fs_id_p
        AND iil.inode_number = inode_number_p
        AND ii.status = old_status_p;

        UPDATE inodes AS ino
        SET mtime = mtime_p, ctime = ctime_p, last_modification = last_modification_p
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = inode_number_p;

    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_inode_info_updating_times_and_writers(fs_id_p BIGINT, inode_number_p BIGINT, atime_p BIGINT, ctime_p BIGINT, last_usage_p BIGINT, write_p BOOLEAN)
RETURNS TABLE(inode_number BIGINT, uid BIGINT, gid BIGINT, mode BIGINT, size BIGINT, atime BIGINT, ctime BIGINT, mtime BIGINT, last_usage BIGINT, last_modification BIGINT, nlink BIGINT, dirty_writers BIGINT, in_cache BOOLEAN, digest TEXT, digest_type SMALLINT) AS $$
DECLARE
    in_cache_var BOOLEAN;
BEGIN
    BEGIN
        SELECT ino.in_cache INTO in_cache_var
        FROM inodes AS ino
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = inode_number_p
        FOR UPDATE;

        IF FOUND THEN

            UPDATE inodes AS ino
            SET atime = atime_p, ctime = ctime_p, last_usage = last_usage_p
            WHERE ino.fs_id = fs_id_p
            AND ino.inode_number = inode_number_p;

            IF in_cache_var AND write_p THEN
                UPDATE inodes AS ino
                SET dirty_writers = ino.dirty_writers + 1
                WHERE ino.fs_id = fs_id_p
                AND ino.inode_number = inode_number_p;
            END IF;

        END IF;

        RETURN QUERY SELECT ino.inode_number, ino.uid, ino.gid, ino.mode, ino.size, ino.atime, ino.ctime, ino.mtime, ino.last_usage, ino.last_modification, ino.nlink, ino.dirty_writers, ino.in_cache, ino.digest, ino.digest_type
        FROM inodes AS ino
        WHERE ino.inode_number = inode_number_p
        AND ino.fs_id = fs_id_p;
        RETURN;
    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION remove_dir_entry(fs_id_p BIGINT, parent_inode_num_p BIGINT, dir_entry_name_p TEXT, ctime_p BIGINT)
RETURNS TABLE (return_code SMALLINT, inode_number BIGINT) AS $$
DECLARE
    inode_number_var BIGINT;
    entry_id_var BIGINT;
    type_var SMALLINT;
    nlink_var BIGINT;
    children_count_var BIGINT;
BEGIN
    BEGIN
        LOCK TABLE entries IN SHARE ROW EXCLUSIVE MODE;

        -- get the existing entry
        SELECT ent.type, ent.inode_number, ent.entry_id INTO type_var, inode_number_var, entry_id_var
        FROM entries AS ent
        INNER JOIN entries AS parent_ent ON ent.fs_id = parent_ent.fs_id
        AND ent.parent_entry_id = parent_ent.entry_id
        INNER JOIN inodes AS ino ON ent.fs_id = ino.fs_id
        AND ent.inode_number = ino.inode_number
        WHERE parent_ent.inode_number = parent_inode_num_p
        AND ent.fs_id = fs_id_p
        AND ent.name = dir_entry_name_p;

        IF FOUND THEN
            IF type_var = 2 THEN
                -- it is a directory
                -- is it empty?
                SELECT count(ent.inode_number) INTO children_count_var
                FROM entries AS ent
                WHERE ent.fs_id = fs_id_p
                AND ent.parent_entry_id = entry_id_var;

                IF children_count_var = 0 THEN

                    -- remove the entry
                    DELETE FROM entries AS ent
                    WHERE ent.entry_id = entry_id_var
                    AND ent.fs_id = fs_id_p;

                    -- update the parent's ctime and mtime
                    UPDATE inodes AS ino
                    SET mtime = ctime_p, ctime = ctime_p
                    WHERE ino.inode_number = parent_inode_num_p
                    AND ino.fs_id = fs_id_p;

                    -- decrement the linked inode usage
                    SELECT * INTO STRICT nlink_var
                    FROM decrement_inode_usage(inode_number_var, fs_id_p, ctime_p);

                    RETURN QUERY SELECT 0::SMALLINT AS return_code, inode_number_var AS inode_number;
                    RETURN;

                ELSE
                    -- return ENOTEMPTY
                    RETURN QUERY SELECT 39::SMALLINT AS return_code, 0::BIGINT AS inode_number;
                    RETURN;
                END IF;
            ELSE
                -- return ENOTDIR
                RETURN QUERY SELECT 20::SMALLINT AS return_code, 0::BIGINT AS inode_number;
                RETURN;
            END IF;
        ELSE
            -- return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS inode_number;
            RETURN;
        END IF;
    END;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION remove_inode_entry(fs_id_p BIGINT, parent_inode_num_p BIGINT, entry_name_p TEXT, ctime_p BIGINT)
RETURNS TABLE (return_code SMALLINT, inode_number BIGINT, deleted BOOLEAN) AS $$
DECLARE
    inode_number_var BIGINT;
    entry_id_var BIGINT;
    type_var SMALLINT;
    nlink_var BIGINT;
    deleted_var BOOLEAN;
BEGIN
    BEGIN

        -- get the existing entry
        SELECT ent.type, ent.inode_number, ent.entry_id INTO type_var, inode_number_var, entry_id_var
        FROM entries AS ent
        INNER JOIN entries AS parent_ent ON ent.fs_id = parent_ent.fs_id
        AND ent.parent_entry_id = parent_ent.entry_id
        WHERE parent_ent.inode_number = parent_inode_num_p
        AND ent.fs_id = fs_id_p
        AND ent.name = entry_name_p
        FOR UPDATE;

        IF FOUND THEN

            IF type_var <> 2 THEN

                -- remove the entry
                DELETE FROM entries AS ent
                WHERE ent.entry_id = entry_id_var
                AND ent.fs_id = fs_id_p;

                -- update the parent's ctime and mtime
                UPDATE inodes AS ino
                SET mtime = ctime_p, ctime = ctime_p
                WHERE ino.inode_number = parent_inode_num_p
                AND ino.fs_id = fs_id_p;

                -- decrement the linked inode usage
                SELECT * INTO STRICT nlink_var
                FROM decrement_inode_usage(inode_number_var, fs_id_p, ctime_p);

                -- if the inode usage count is down to 0
                IF nlink_var = 0 THEN
                    deleted_var := true;
                ELSE
                    deleted_var := false;
                END IF;

                RETURN QUERY SELECT 0::SMALLINT AS return_code, inode_number_var AS inode_number, deleted_var AS deleted;
                RETURN;

            ELSE
                -- we are not going to unlink a directory
                -- return EISDIR
                RETURN QUERY SELECT 21::SMALLINT AS return_code, 0::BIGINT AS inode_number, false::BOOLEAN AS deleted;
                RETURN;
            END IF;
        ELSE
            -- return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS inode_number, false::BOOLEAN AS deleted;
            RETURN;
        END IF;
    END;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rename_inode_entry(fs_id_p BIGINT, old_parent_inode_num_p BIGINT, old_entry_name_p TEXT, new_parent_inode_num_p BIGINT, new_entry_name_p TEXT, ctime_p BIGINT)
RETURNS TABLE (return_code SMALLINT, renamed_inode_number BIGINT, deleted_inode_number BIGINT, deleted BOOLEAN) AS $$
DECLARE
    renamed_inode_number_var BIGINT;
    renamed_entry_id_var BIGINT;
    renamed_type_var SMALLINT;
    deleted_inode_number_var BIGINT;
    deleted_entry_id_var BIGINT;
    deleted_type_var SMALLINT;
    new_parent_entry_id_var BIGINT;
    nlink_var BIGINT;
    deleted_var BOOLEAN;
    children_count_var BIGINT;
BEGIN
    BEGIN
        LOCK TABLE entries IN SHARE ROW EXCLUSIVE MODE;

        -- retrieve the existing entry we are going to rename
        SELECT ent.type, ent.inode_number, ent.entry_id INTO renamed_type_var, renamed_inode_number_var, renamed_entry_id_var
        FROM entries AS ent
        INNER JOIN entries AS parent_ent ON ent.fs_id = parent_ent.fs_id
        AND ent.parent_entry_id = parent_ent.entry_id
        WHERE parent_ent.inode_number = old_parent_inode_num_p
        AND ent.fs_id = fs_id_p
        AND ent.name = old_entry_name_p;

        IF NOT FOUND THEN
            -- return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS renamed_inode_number, 0::BIGINT AS deleted_inode_number, false::BOOLEAN AS deleted;
            RETURN;
        END IF;

        deleted_var := false;

        -- retrieve the new parent
        SELECT ent.entry_id INTO new_parent_entry_id_var
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND ent.inode_number = new_parent_inode_num_p;

        IF NOT FOUND THEN
            -- return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS renamed_inode_number, 0::BIGINT AS deleted_inode_number, false::BOOLEAN AS deleted;
            RETURN;
        END IF;

        -- check whether there is already an entry with the same
        -- parent and name
        SELECT ent.type, ent.inode_number, ent.entry_id INTO deleted_type_var, deleted_inode_number_var, deleted_entry_id_var
        FROM entries AS ent
        INNER JOIN entries AS parent_ent ON ent.fs_id = parent_ent.fs_id
        AND ent.parent_entry_id = parent_ent.entry_id
        WHERE parent_ent.inode_number = new_parent_inode_num_p
        AND ent.fs_id = fs_id_p
        AND ent.name = new_entry_name_p;

        IF FOUND THEN
            -- we are trying to overwrite an existing entry
            IF deleted_type_var = 2 THEN
                IF renamed_type_var <> 2 THEN
                    -- the existing entry is a directory,
                    -- the new one is not, return EISDIR
                    RETURN QUERY SELECT 21::SMALLINT AS return_code, 0::BIGINT AS renamed_inode_number, 0::BIGINT AS deleted_inode_number, false::BOOLEAN AS deleted;
                    RETURN;
                END IF;

                -- check whether the existing entry is empty
                SELECT count(entry_id) INTO STRICT children_count_var
                FROM entries AS ent
                WHERE ent.fs_id = fs_id_p
                AND ent.parent_entry_id = deleted_entry_id_var;

                IF children_count_var > 0 THEN
                    -- we cannot overwrite a non-empty directory
                    -- return ENOTEMPTY
                    RETURN QUERY SELECT 39::SMALLINT AS return_code, 0::BIGINT AS renamed_inode_number, 0::BIGINT AS deleted_inode_number, false::BOOLEAN AS deleted;
                    RETURN;
                END IF;

            END IF;

            -- remove the existing entry
            DELETE FROM entries AS ent
            WHERE ent.entry_id = deleted_entry_id_var
            AND ent.fs_id = fs_id_p;

            -- decrement the existing entry's inode usage
            SELECT * INTO STRICT nlink_var
            FROM decrement_inode_usage(deleted_inode_number_var, fs_id_p, ctime_p);

            -- if the existing inode has been deleted
            IF nlink_var = 0 THEN
                deleted_var := true;
            END IF;

        END IF;

        -- update the renamed entry parent and name
        UPDATE entries AS ent
        SET name = new_entry_name_p, parent_entry_id = new_parent_entry_id_var
        WHERE ent.fs_id = fs_id_p
        AND ent.entry_id = renamed_entry_id_var;

        -- update the ctime of the inode linked to the renamed entry
        UPDATE inodes AS ino
        SET ctime = ctime_p
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = renamed_inode_number_var;

        -- update the old parent ctime
        UPDATE inodes AS ino
        SET ctime = ctime_p
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = old_parent_inode_num_p;

        -- update the new parent ctime
        UPDATE inodes AS ino
        SET ctime = ctime_p
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = new_parent_inode_num_p;

        RETURN QUERY SELECT 0::SMALLINT AS return_code, renamed_inode_number_var AS renamed_inode_number, deleted_inode_number_var AS deleted_inode_number, deleted_var AS deleted;
        RETURN;

    END;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_full_path_from_parent_and_name(fs_id_p BIGINT, parent_inode_num_p BIGINT, entry_name_p TEXT)
RETURNS TEXT as $$
DECLARE
    inode_number_var BIGINT;
    parent_entry_id_var BIGINT;
    parent_entry_name_var TEXT;
    full_path_var TEXT;
BEGIN

    full_path_var := '/';

    IF parent_inode_num_p IS NOT NULL THEN

        SELECT ent.entry_id INTO STRICT parent_entry_id_var
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND ent.inode_number = parent_inode_num_p;

        full_path_var := full_path_var || entry_name_p;

        <<innerloop>>
        LOOP
            BEGIN
                SELECT ent.name, ent.parent_entry_id INTO STRICT parent_entry_name_var, parent_entry_id_var
                FROM entries AS ent
                WHERE ent.fs_id = fs_id_p AND
                ent.entry_id = parent_entry_id_var;

                IF parent_entry_id_var IS NOT NULL THEN
                    full_path_var := '/' || parent_entry_name_var || full_path_var;
                ELSE
                    EXIT innerloop;
                END IF;

            END;
        END LOOP;
    END IF;

    RETURN full_path_var;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION add_hardlink(fs_id_p BIGINT, existing_inode_number_p BIGINT, new_parent_inode_number_p BIGINT, new_entry_name_p TEXT, type_p SMALLINT, ctime_p BIGINT)
RETURNS TABLE(return_code SMALLINT, inode_number BIGINT, uid BIGINT, gid BIGINT, mode BIGINT, size BIGINT, atime BIGINT, ctime BIGINT, mtime BIGINT, last_usage BIGINT, last_modification BIGINT, nlink BIGINT, dirty_writers BIGINT, in_cache BOOLEAN, digest TEXT, digest_type SMALLINT) AS $$
DECLARE
    parent_type_var SMALLINT;
    parent_entry_id_var BIGINT;
    existing_type_var SMALLINT;
    existing_link_to_var TEXT;
BEGIN
    BEGIN
        LOCK TABLE entries IN SHARE ROW EXCLUSIVE MODE;

        -- check that the inode we are hardlinking to exists
        PERFORM ino.inode_number
        FROM inodes AS ino
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = existing_inode_number_p
        FOR UPDATE;

        IF NOT FOUND THEN
            -- otherwise, return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS inode_number, 0::BIGINT AS uid, 0::BIGINT AS gid, 0::BIGINT as mode, 0::BIGINT AS size, 0::BIGINT AS atime, 0::BIGINT AS ctime, 0::BIGINT AS mtime, 0::BIGINT as last_usage, 0::BIGINT AS last_modification, 0::BIGINT AS nlink, 0::BIGINT AS dirty_writers, false AS in_cache, NULL::TEXT as digest, 0::SMALLINT AS digest_type;
            RETURN;
        END IF;

        -- now we check that the new parent exists and is a directory
        SELECT ent.type, ent.entry_id INTO parent_type_var, parent_entry_id_var
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND ent.inode_number = new_parent_inode_number_p;

        IF NOT FOUND THEN
            -- no parent, return ENOENT
            RETURN QUERY SELECT 2::SMALLINT AS return_code, 0::BIGINT AS inode_number, 0::BIGINT AS uid, 0::BIGINT AS gid, 0::BIGINT as mode, 0::BIGINT AS size, 0::BIGINT AS atime, 0::BIGINT AS ctime, 0::BIGINT AS mtime, 0::BIGINT as last_usage, 0::BIGINT AS last_modification, 0::BIGINT AS nlink, 0::BIGINT AS dirty_writers, false AS in_cache, NULL::TEXT as digest, 0::SMALLINT AS digest_type;
            RETURN;
        END IF;

        IF parent_type_var <> 2 THEN
            -- not a directory, return ENOTDIR
            RETURN QUERY SELECT 20::SMALLINT AS return_code, 0::BIGINT AS inode_number, 0::BIGINT AS uid, 0::BIGINT AS gid, 0::BIGINT as mode, 0::BIGINT AS size, 0::BIGINT AS atime, 0::BIGINT AS ctime, 0::BIGINT AS mtime, 0::BIGINT as last_usage, 0::BIGINT AS last_modification, 0::BIGINT AS nlink, 0::BIGINT AS dirty_writers, false AS in_cache, NULL::TEXT as digest, 0::SMALLINT AS digest_type;
            RETURN;
        END IF;

        -- check that there is no existing entry with the same
        -- parent and the same name
        PERFORM ent.entry_id
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND ent.parent_entry_id = parent_entry_id_var
        AND ent.name = new_entry_name_p;

        IF FOUND THEN
            -- there is one, return EEXIST
            RETURN QUERY SELECT 17::SMALLINT AS return_code, 0::BIGINT AS inode_number, 0::BIGINT AS uid, 0::BIGINT AS gid, 0::BIGINT as mode, 0::BIGINT AS size, 0::BIGINT AS atime, 0::BIGINT AS ctime, 0::BIGINT AS mtime, 0::BIGINT as last_usage, 0::BIGINT AS last_modification, 0::BIGINT AS nlink, 0::BIGINT AS dirty_writers, false AS in_cache, NULL::TEXT as digest, 0::SMALLINT AS digest_type;
            RETURN;
        END IF;

        -- get an existing entry linked to the inode we are
        -- hardlinking to
        SELECT type, link_to INTO existing_type_var, existing_link_to_var
        FROM entries AS ent
        WHERE ent.fs_id = fs_id_p
        AND ent.inode_number = existing_inode_number_p;

        IF existing_type_var = 2 THEN
            -- directories can't be hardlinked on linux
            -- return EPERM
            RETURN QUERY SELECT 1::SMALLINT AS return_code, 0::BIGINT AS inode_number, 0::BIGINT AS uid, 0::BIGINT AS gid, 0::BIGINT as mode, 0::BIGINT AS size, 0::BIGINT AS atime, 0::BIGINT AS ctime, 0::BIGINT AS mtime, 0::BIGINT as last_usage, 0::BIGINT AS last_modification, 0::BIGINT AS nlink, 0::BIGINT AS dirty_writers, false AS in_cache, NULL::TEXT as digest, 0::SMALLINT AS digest_type;
            RETURN;
        END IF;

        -- insert the new entry
        INSERT INTO entries(fs_id, inode_number, type, name, link_to, parent_entry_id)
        VALUES (fs_id_p, existing_inode_number_p, existing_type_var, new_entry_name_p, existing_link_to_var, parent_entry_id_var);

        -- update the nlink and ctime of the inode
        UPDATE inodes AS ino
        SET nlink = ino.nlink + 1, ctime = ctime_p
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = existing_inode_number_p;

        -- update the new parent's ctime and mtime
        UPDATE inodes AS ino
        SET mtime = ctime_p, ctime = ctime_p
        WHERE ino.fs_id = fs_id_p
        AND ino.inode_number = new_parent_inode_number_p;

        -- return the content of the inode
        RETURN QUERY SELECT 0::SMALLINT AS return_code, ino.inode_number, ino.uid, ino.gid, ino.mode, ino.size, ino.atime, ino.ctime, ino.mtime, ino.last_usage, ino.last_modification, ino.nlink, ino.dirty_writers, ino.in_cache, ino.digest, ino.digest_type
        FROM inodes AS ino
        WHERE ino.inode_number = existing_inode_number_p
        AND ino.fs_id = fs_id_p;
        RETURN;

    END;
END;
$$ LANGUAGE plpgsql;
