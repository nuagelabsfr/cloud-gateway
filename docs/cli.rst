Command Line Interface
======================

CloudGatewayAddFilesystem
-------------------------

This command adds a new filesystem to the Storage Manager configuration
file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilesystem
    Id, type, cache-root, full-threshold, and file parameters are mandatory.
    Usage: CloudGatewayAddFilesystem [OPTIONS] [<instance name>] ...
    Required options are:
            -i --id                        Filesystem ID
            -t --type                      Filesystem type, eg Single, Mirroring or Striping
            -c --cache-root                Filesystem cache root directory
            -u --full-threshold            Full Threshold, in percent
            -f --file                      Configuration file
            -m --mount-point               Mount Point
    Optional options are:
            -o --io-block-size             Preferred I/O block size, in bytes
            -s --clean-min-file-size       The minimum file size in bytes for an object
                                           to be considered by the cache cleaning process
            -a --clean-max-access-offset   Only files that have been not been accessed for
                                           at least this value (in seconds) might be cleaned

Parameters
~~~~~~~~~~

-  **Filesystem identifier (-i --id)** the new filesystem’s identifier,
   or name.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to update.

-  **Filesystem type (-t --type)** the new filesystem’s type. Three
   modes are available:

   -  **Single**, where the filesystem uses only on instance ;

   -  **Mirroring**, where data are mirrored on each instance associated
      with the filesystem ;

   -  **Striping**, where data are distributed over all instance
      associated with the filesystem.

   See `Configuration/FileSystems/FileSystem/Type <configuration_options.html#configuration-filesystems-filesystem-type>`_.

-  **Cache root (-c --cache-root)** the root cache directory of the new
   filesystem.

   See `Configuration/FileSystems/FileSystem/CacheRoot <configuration_options.html#configuration-filesystems-filesystem-cacheroot>`_.

-  **Full threshold (-u --full-threshold)** the full threshold of the
   new filesystem, over which the cleaner begins to expunge cache
   entries.

   See `Configuration/FileSystems/FileSystem/FullThreshold <configuration_options.html#configuration-filesystems-filesystem-fullthreshold>`_.

-  **I/O block size (-o --io-block-size)** the new filesystem’s
   preferred I/O block size, in bytes.

   See `Configuration/FileSystems/FileSystem/IOBlockSize <configuration_options.html#configuration-filesystems-filesystem-ioblocksize>`_.

-  **Cleaner minimum file size (-s --clean-min-file-size)** the new
   filesystem’s cleaner minimum file size. Files smaller than this size
   won’t get expunged from the cache.

   See `Configuration/FileSystems/FileSystem/CleanMinFileSize <configuration_options.html#configuration-filesystems-filesystem-cleanminfilesize>`_.

-  **Cleaner maximum access offset (-a --clean-max-access-offset)** the
   new filesystem’s cleaner maximum offset. Only files that have not
   been accessed for at least as many seconds are considered for
   cleaning.

   See `Configuration/FileSystems/FileSystem/CleanMaxAccessOffset <configuration_options.html#configuration-filesystems-filesystem-cleanmaxaccessoffset>`_.

-  **Configuration file (-m --mount-point)** the mount point where the
   filesystem will be mounted.

CloudGatewayAddFilterToInstance
-------------------------------

This command adds a filter to an existing instance.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilterToInstance
    Name, type and file parameters are mandatory.
    Usage: CloudGatewayAddFilterToInstance [OPTIONS]
    Required options are:
            -i --instance-name                       Instance name
            -t --type                                Filter type (Compression, Encryption)
            -f --file                                Configuration file
    Optional options are:
            -l --level                               Compression Level (required for
                                                     Compression filter)
            -c --cipher                              Cipher (required for Encryption filter)
            -d --digest                              Digest used to derive an encryption key
                                                     (required for Encryption filter)
            -k --key-iteration-count                 Count of iterations used to derive an encryption
                                                     key (required for Encryption filter)
            -p --password                            Password used to derive an encryption key
                                                     (required for Encryption filter)
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Instance identifier (-i --id)** the existing instance’s name.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to update.

-  **Filter type (-t --type)** the new filter’s type. Two filter types
   are available:

   -  **Compression**, compressing file content on-the-fly before
      sending it to the Cloud ;

   -  **Encryption**, encrypting file content on-the-fly before sending
      it to the Cloud.

   See `Configuration/Instances/Instance/Filters/Filter/Type <configuration_options.html#configuration-instances-instance-filters-filter-type>`_.

-  **Level (-l --level)** the compression level used by the compression
   filter. Valid levels range from 1 to 9, 1 being the fastest and 9 the
   most efficient, albeit slowest and memory consuming.

   See `Configuration/Instances/Instance/Filters/Filter/Specifics/Level <configuration_options.html#configuration-instances-instance-filters-filter-specifics-level>`_.

-  **Cipher (-c --cipher)** the cipher used by the encryption filter.

   See `Configuration/Instances/Instance/Filters/Filter/Specifics/Cipher <configuration_options.html#configuration-instances-instance-filters-filter-specifics-cipher>`_.

-  **Digest (-d --digest)** the digest used to derive an encryption key
   from the password, with the encryption filter.

   See `Configuration/Instances/Instance/Filters/Filter/Specifics/Digest <configuration_options.html#configuration-instances-instance-filters-filter-specifics-digest>`_.

-  **Key iteration count (-k --key-iteration-count)** the number of
   iterations used to derive an encryption key from the password, with
   the encryption filter.

   See `Configuration/Instances/Instance/Filters/Filter/Specifics/KeyIterationCount <configuration_options.html#configuration-instances-instance-filters-filter-specifics-keyiterationcount>`_.

-  **Password (-p --password)** the password used to derive an
   encryption key, with the encryption filter.

   See `Configuration/Instances/Instance/Filters/Filter/Specifics/Password <configuration_options.html#configuration-instances-instance-filters-filter-specifics-password>`_.

CloudGatewayAddInstance
-----------------------

This command adds a new instance to the Storage Manager configuration
file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayAddInstance
    Name, provider and file parameters are mandatory.
    Usage: CloudGatewayAddInstance [OPTIONS]
    Required options are:
            -n --name                                Instance name
            -P --provider                            Provider type (Amazon, Openstack)
            -f --file                                Configuration file
    Optional options are:
            -a --access-key-id                       Access Key ID (required for type Amazon)
            -s --secret-access-key                   Secret Access Key (required for type Amazon)
            -e --endpoint                            Endpoint (required for type Amazon)
            -g --endpoint-port                       Endpoint port (required for type Amazon)
            -b --bucket                              Bucket (required for type Amazon)
            -S --secure-transaction                  Whether to use HTTPs (required for Amazon)
            -i --identity-version                    Identity Version for Openstack (required for Openstack)
            -u --user-name                           Username (required for Openstack)
            -p --password                            Password (required for Openstack v2)
            -t --tenant-id                           Tenant ID
            -T --tenant-name                         Tenant Name
            -I --api-access-key                      API Access Key (required for Openstack v1)
            -A --authentication-endpoint             Authentication Endpoint (required for Openstack)
            -c --container                           Container (required for Openstack)
            -r --preferred-region                    Preferred region to use with Openstack, if any
            -m --authentication-max-life-time        Authentication max lifetime for an Openstack token
            -R --authentication-token-recent-delay   An Openstack authentication error with a token older than
                                                     this delay will trigger a re-authentication
            -F --authentication-format               Authentication format (optional for Openstack)
            -k --allow-insecure                      Allow insecure (invalid certificate) communication
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Instance name (-n --name)** the new instance’s name, or identifier.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to update.

-  **Provider type -P --provider** the new instance’s provider type, two
   types are available:

   -  **Amazon**, all providers compatible with the S3 API ;

   -  **Openstack**, all providers compatible with the Openstack Swift
      API.

   See `Configuration/Instances/Instance/Provider <configuration_options.html#configuration-instances-instance-provider>`_.

-  **Access key identifier (-a --access-key-id)** the access key
   identifier, required when using a S3 provider.

   See `Configuration/Instances/Instance/Specifics/AccessKeyId <configuration_options.html#configuration-instances-instance-specifics-accesskeyid>`_.

-  **Secret access key (-s --secret-access-key)** the secret access key,
   required when using a S3 provider.

   See `Configuration/Instances/Instance/Specifics/SecretAccessKey <configuration_options.html#configuration-instances-instance-specifics-secretaccesskey>`_.

-  **Endpoint (-e --endpoint)** the cloud provider endpoint, required
   when using a S3 provider.

   See `Configuration/Instances/Instance/Specifics/Endpoint <configuration_options.html#configuration-instances-instance-specifics-endpoint>`_.

-  **Endpoint port (-g --endpoint-port)** the cloud provider endpoint
   port, required when using a S3 provider.

   See `Configuration/Instances/Instance/Specifics/EndpointPort <configuration_options.html#configuration-instances-instance-specifics-endpointport>`_.

-  **Bucket (-b --bucket)** an existing bucket to use, required when
   using a S3 provider.

   See `Configuration/Instances/Instance/Specifics/Bucket <configuration_options.html#configuration-instances-instance-specifics-bucket>`_.

-  **Secure transaction (-S --secure-transaction)** whether to use
   SSL/TLS to secure transfers, required when using a S3 provider.

   See `Configuration/Instances/Instance/Specifics/SecureTransaction <configuration_options.html#configuration-instances-instance-specifics-securetransaction>`_.

-  **Identity version (-i --identity-version)** the Openstack Swift
   identity version to use, required when using an Openstack provider.

   See `Configuration/Instances/Instance/Specifics/IdentityVersion <configuration_options.html#configuration-instances-instance-specifics-identityversion>`_.

-  **Username (-u --user-name)** the username used to authenticate to
   the storage provider, required when using an Openstack provider.

   See `Configuration/Instances/Instance/Specifics/Username <configuration_options.html#configuration-instances-instance-specifics-username>`_.

-  **Password (-p --password)** the password used to authenticate to the
   storage provider, required when using an Openstack provider and
   identity v2.

   See `Configuration/Instances/Instance/Specifics/Password <configuration_options.html#configuration-instances-instance-specifics-password>`_.

-  **Tenant ID (-t --tenant-id)** the tenant ID used to authenticate to
   the storage provider, required when using an Openstack provider and
   identity v2 with a tenant ID.

   See `Configuration/Instances/Instance/Specifics/TenantId <configuration_options.html#configuration-instances-instance-specifics-tenantid>`_.

-  **Tenant name (-T --tenant-name)** the tenant name used to
   authenticate to the storage provider, required when using an
   Openstack provider and identity v2 with a tenant name.

   See `Configuration/Instances/Instance/Specifics/TenantName <configuration_options.html#configuration-instances-instance-specifics-tenantname>`_.

-  **API access key (-I --api-access-key)** the API access key used to
   authenticate to the storage provider, required when using an
   Openstack provider and identity v1.

   See `Configuration/Instances/Instance/Specifics/APIAccessKey <configuration_options.html#configuration-instances-instance-specifics-apiaccesskey>`_.

-  **Authentication endpoint (-A --authentication-endpoint)** the cloud
   storage provider authentication endpoint, required when using an
   Openstack provider.

   See `Configuration/Instances/Instance/Specifics/AuthenticationEndpoint <configuration_options.html#configuration-instances-instance-specifics-authenticationendpoint>`_.

-  **Container (-c --container)** an existing container to use, required
   when using an Openstack provider.

   See `Configuration/Instances/Instance/Specifics/Container <configuration_options.html#configuration-instances-instance-specifics-container>`_.

-  **Preferred region (-r --preferred-region)** the preferred region to
   use, if any, when using an Openstack provider.

   See `Configuration/Instances/Instance/Specifics/PreferredRegion <configuration_options.html#configuration-instances-instance-specifics-preferredregion>`_.

-  **Authentication maximum lifetime (-m
   --authentication-max-life-time)** the maximum lifetime of an
   Openstack token.

   See `Configuration/Instances/Instance/Specifics/AuthenticationMaxLifetime <configuration_options.html#configuration-instances-instance-specifics-authenticationmaxlifetime>`_.

-  **Authentication recent token delay (-R
   --authentication-recent-token-delay)** authentication error when
   using an Openstack token older than this delay will trigger a
   re-authentication attempt.

   See `Configuration/Instances/Instance/Specifics/AuthenticationTokenRecentDelay <configuration_options.html#configuration-instances-instance-specifics-authenticationtokenrecentdelay>`_.

-  **Authentication Format (-F
   --authentication-format)** the authentication format used for
   Openstack.

   See `Configuration/Instances/Instance/Specifics/AuthenticationFormat <configuration_options.html#configuration-instances-instance-specifics-authenticationformat>`_.

-  **Allow insecure connection (-k --allow-insecure)** allows the cloud
   provider to present an invalid certificate. This means that the
   transfer will not be secured.

   See `Configuration/Instances/Instance/Specifics/AllowInsecureHTTPS <configuration_options.html#configuration-instances-instance-specifics-allowinsecurehttps>`_.

CloudGatewayListFilesystems
---------------------------

This command lists all filesystems (also known as volumes) present in
the given configuration file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayListFilesystems
    File parameter is mandatory.
    Usage: CloudGatewayListFilesystems [OPTIONS]
    Required options are:
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to read information from.

CloudGatewayListInstances
-------------------------

This command lists all instances existing in the given configuration
file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayListInstances
    File parameter is mandatory.
    Usage: CloudGatewayListInstances [OPTIONS]
    Required options are:
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to read information from.

CloudGatewayMount
-----------------

This command mounts the filesystem (also known as volume) specified in
the given configuration file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayMount
    Usage: $0 [<Mount point>] <Configuration File>

Parameters
~~~~~~~~~~

-  **Mount point** the directory where the filesystem should be mounted.
   This is only required if the *MountPoint* value does not exist in the
   configuration file.

   See `Configuration/FileSystems/FileSystem/MountPoint <configuration_options.html#configuration-filesystems-filesystem-mountpoint>`_.

-  **Configuration file** the mount point configuration file.

CloudGatewayMountConfigTest
---------------------------

This command parses the given filesystem configuration file, in order to
verify that it is valid.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayMountConfigTest
    CloudGatewayMountConfigTest <Cloud Gateway mount configuration file>

Parameters
~~~~~~~~~~

-  **Configuration file** the mount point configuration file.

CloudGatewayRemoveFilesystem
----------------------------

This command removes an existing filesystem definition from the Cloud
Gateway configuration file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayRemoveFilesystem
    Name, type and file parameters are mandatory.
    Usage: CloudGatewayRemoveFilesystem [OPTIONS]
    Required options are:
            -i --id                                  Filesystem ID
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Filesystem identifier (-i --id)** the name of the filesystem (or
   volume) to remove.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to update.

CloudGatewayRemoveFilterFromInstance
------------------------------------

This command removes an existing filter associated to an instance from
the Cloud Gateway configuration file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayRemoveFilterFromInstance
    Name, type and file parameters are mandatory.
    Usage: CloudGatewayRemoveFilterFromInstance [OPTIONS]
    Required options are:
            -i --instance-name                       Instance name
            -t --type                                Filter type (Compression, Encryption)
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Instance identifier (-i --instance-name)** the name of the instance
   whose filter has to be removed.

-  **Filter type (-f --type)** the type of the filter to be removed.

   See `Configuration/Instances/Instance/Filters/Filter/Type <configuration_options.html#configuration-instances-instance-filters-filter-type>`_.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to update.

CloudGatewayRemoveInstance
--------------------------

This command removes an existing instance from the Cloud Gateway
configuration file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayRemoveInstance
    Name and file parameters are mandatory.
    Usage: CloudGatewayRemoveInstance [OPTIONS]
    Required options are:
            -i --instance-name                       Instance name
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Instance identifier (-i --instance-name)** the name of the instance
   to remove.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file to update.

CloudGatewayShowFilesystem
--------------------------

This command displays a filesystem’s configuration.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayShowFilesystem
    Id and file parameters are mandatory.
    Usage: CloudGatewayShowFilesystem [OPTIONS]
    Required options are:
            -i --id                                  Filesystem ID
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Filesystem identifier (-i --id)** the filesystem identifier.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file.

CloudGatewayShowInstance
------------------------

This command displays an instance’s configuration.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayShowInstance
    Name and file parameters are mandatory.
    Usage: CloudGatewayShowInstance [OPTIONS]
    Required options are:
            -i --instance-name                       Instance name
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Instance identifier (-i --instance-name)** the instance name.

-  **Configuration file (-f --file)** the Cloud Gateway Storage Manager
   configuration file.

CloudGatewayShowMount
---------------------

This command displays a mount point configuration.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayShowMount
    File parameter is mandatory.
    Usage: CloudGatewayShowMount [OPTIONS]
    Required options are:
            -f --file                                Configuration file
    Please look at the product documentation for more information.

Parameters
~~~~~~~~~~

-  **Configuration file (-f --file)** the mount point configuration
   file.

CloudGatewayStatus
------------------

This command displays the number of files (and optionally the status of
each one) that are not synchronised with the cloud storage provider,
either because they have been modified (dirty state) or deleted, and the
modification has not been repercuted to the storage provider yet.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStatus

Parameters
~~~~~~~~~~

-  **Verbose (-v)** displays the status of each deleted or dirty file.

CloudGatewayStorageManager
--------------------------

This command controls the Cloud Gateway Storage Manager.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager
    Usage: ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager \
      [start|stop|graceful-stop|force-stop|restart|reload|status

Options
~~~~~~~

-  **start** Start the Storage Manager.

-  **stop** Stop the Storage Manager using a graceful stop. See on
   page .

-  **graceful-stop** Gracefully stop the Storage Manager. See on page .

-  **force-stop** Alias for graceful-stop.

-  **restart** Stop the Storage Manager using a force stop, then start
   it.

-  **reload** Gracefully reload Storage Manager. See on page .

-  **status** Print whether the Storage Manager is running or not.

CloudGatewayStorageManagerConfigTest
------------------------------------

This command parses the given Storage Manager configuration file, in
order to verify that it is valid.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManagerConfigTest
    CloudGatewayStorageManagerConfigTest <Cloud Gateway Storage Manager configuration file>

Parameters
~~~~~~~~~~

-  **Configuration file** the Storage Manager configuration file.

CloudGatewayStorageManagerUnMount
---------------------------------

This command unmounts the filesystem (also known as volume) specified in
the given configuration file.

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayUnmount
    Usage: ${INSTALL_PREFIX}/bin/CloudGatewayUnmount [<Mount point>|<Configuration File>]

Parameters
~~~~~~~~~~

-  **Mount point** the directory where the filesystem is mounted.

   See `Configuration/FileSystems/FileSystem/MountPoint <configuration_options.html#configuration-filesystems-filesystem-mountpoint>`_.

-  **Configuration file** the mount point configuration file.
