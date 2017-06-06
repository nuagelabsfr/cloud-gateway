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

#include <errno.h>

#include <cgfs.h>

#include <cloudutils/cloudutils_xml.h>
#include <cloudutils/cloudutils_configuration.h>

cgfs_data * cgfs_get_data(void)
{
    static cgfs_data data;

    return &data;
}

int cgfs_init(void)
{
    int result = cgutils_xml_init();

    if (result == 0)
    {
        result = cgutils_configuration_init();
    }

    return result;
}

void cgfs_destroy(void)
{
    cgutils_configuration_destroy();
    cgutils_xml_destroy();
}

 void cgfs_data_clean(cgfs_data ** data)
{
    if (data != NULL &&
        *data != NULL)
    {
        cgfs_data * this = *data;

        if (this->cache != NULL)
        {
            cgfs_cache_free(this->cache), this->cache = NULL;
        }

        if (this->cgsmc_data != NULL)
        {
            cgsmc_async_data_free(this->cgsmc_data), this->cgsmc_data = NULL;
        }

        if (this->aio != NULL)
        {
            cgutils_aio_free(this->aio), this->aio = NULL;
        }

        if (this->event_data != NULL)
        {
            cgutils_event_destroy(this->event_data), this->event_data = NULL;
        }

        CGUTILS_FREE(this->cgsm_configuration_file);
        CGUTILS_FREE(this->pid_file);
        CGUTILS_FREE(this->fs_name);
        CGUTILS_FREE(this->buffer);
        this->buffer_size = 0;
    }
}

int cgfs_data_load_configuration(cgfs_data * const this)
{
    CGUTILS_ASSERT(this != NULL);
    CGUTILS_ASSERT(this->event_data != NULL);
    CGUTILS_ASSERT(this->cgsm_configuration_file != NULL);
    CGUTILS_ASSERT(this->fs_name != NULL);

    int result = cgsmc_async_data_init(this->fs_name,
                                       this->cgsm_configuration_file,
                                       this->event_data,
                                       &(this->cgsmc_data));

    if (result == 0)
    {
        result = cgfs_cache_init(&(this->cache));

        if (result != 0)
        {
            CGUTILS_ERROR("Error in cache init: %d",
                          result);
        }
    }
    else
    {
        CGUTILS_ERROR("Error initializing the communication to the storage manager: %d",
                      result);
    }

    return result;
}

uint64_t cgfs_translate_inode_number(cgfs_data const * const data,
                                     uint64_t const ino)
{
    uint64_t result = ino;

    CGUTILS_ASSERT(data != NULL);

    if (COMPILER_UNLIKELY(ino == 1 &&
                          data->root_inode_number > 0))
    {
        result = data->root_inode_number;
    }

    return result;
}
