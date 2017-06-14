Configuration
=============

Components overview
-------------------

.. image:: images/schema-internal-01-01.png
   :alt: Cloud Gateway components overview

Cloud Gateway’s main component is the Storage Manager, a daemon
handling accesses to the filesystem and efficiently managing the
communications with the cloud storage providers. The Storage Manager
itself is composed of 4 different processes:

-  the Storage Server, handling filesystem’s accesses ;

-  the Storage Cleaner, expunging unused files from the cache ;

-  the Storage Monitor, monitoring every storage provider in order to
   provides the best performances ;

-  and the Storage Syncer, syncing the files with the different
   storage providers.

Configuring the Storage Manager
-------------------------------

The Storage Manager associates one or many [8]_ storage spaces [9]_ to
a virtual filesystem. First the storage spaces, named Instances, are
defined, then filesystems. At last, the mapping between filesystems and
instances has to be configured.

Caution: A given instance should not be associated with more than one
filesystem, otherwise collisions and data loss will occur.

Adding a Cloud Storage provider instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Adding an Instance is easy:

Caution: Note that the container / bucket should exist before the
Storage Manager is started.

-  Openstack Swift Identity v1 (Rackspace, ...):

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddInstance -n <Instance Name> \
         -P Openstack \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -i 1 -A <Authentication Endpoint> -c <Container Name> \
         -u <Username> -I <API Key>

-  Openstack Swift Identity v2 with a TenantName (CloudWatt, OVH, ...):

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddInstance -n <Instance Name> \
         -P Openstack \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -i 2 -A <Authentication Endpoint> -c <Container Name> \
         -u <Username> -p <Password> -T <Tenant Name>

-  Openstack Swift Identity v2 with a TenantId (HP, ...):

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddInstance -n <Instance Name> \
         -P Openstack \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -i 2 -A <Authentication Endpoint> -c <Container Name> \
         -u <Username> -p <Password> -t <Tenant Id>

-  S3 (Amazon, Scality, SFR, YaCloud, ...):

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddInstance -n <Instance Name> \
         -P Amazon \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -e <Endpoint> -g <Endpoint Port> -S <false for HTTP, true for HTTPS> \
         -b <Bucket Name> -a <Key> -s <Secret>

Please take care of the fact that the Openstack **Authentication**
**Endpoint** URL does not contain the final **/v1.0/**, **/v1.1/** or
**/v2.0/** part that some providers mention in their documentation, as
it is automatically appended by Cloud Gateway.

Sample values for some common providers are available below, please
note that they may not be valid for your account:

+-------------------------------------------+--------------------------------------------------+
| **Provider**                              | **Endpoint**                                     |
+===========================================+==================================================+
| Amazon S3 (US Standard)                   | s3.amazonaws.com                                 |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (US West Oregon)                | s3-us-west-2.amazonaws.com                       |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (US West Northern California)   | s3-us-west-1.amazonaws.com                       |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (EU Ireland)                    | s3-eu-west-1.amazonaws.com                       |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (Pacific Singapore)             | s3-ap-southeast-1.amazonaws.com                  |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (Pacific Sydney)                | s3-ap-southeast-2.amazonaws.com                  |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (Pacific Tokyo)                 | s3-ap-northeast-1.amazonaws.com                  |
+-------------------------------------------+--------------------------------------------------+
| Amazon S3 (South America Sao Paulo)       | s3-sa-east-1.amazonaws.com                       |
+-------------------------------------------+--------------------------------------------------+
| CloudWatt                                 | https://identity.fr1.cloudwatt.com               |
+-------------------------------------------+--------------------------------------------------+
| OVH                                       | https://lb1.pcs.ovh.net:5443                     |
+-------------------------------------------+--------------------------------------------------+
| Rackspace (US)                            | https://identity.api.rackspacecloud.com          |
+-------------------------------------------+--------------------------------------------------+
| Rackspace (UK)                            | https://lon.identity.api.rackspacecloud.com      |
+-------------------------------------------+--------------------------------------------------+
| SoftLayer (Dallas)                        | https://dal05.objectstorage.softlayer.net/auth   |
+-------------------------------------------+--------------------------------------------------+
| SoftLayer (Amsterdam)                     | https://ams01.objectstorage.softlayer.net/auth   |
+-------------------------------------------+--------------------------------------------------+
| SoftLayer (Singapore)                     | https://sng01.objectstorage.softlayer.net/auth   |
+-------------------------------------------+--------------------------------------------------+

Adding a filesystem using this provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After adding one or more instances, we need to create a virtual
filesystem using them. Cloud Gateway supports 3 filesystem types:

-  Single: the filesystem uses only one instance ;

-  Mirroring: data are mirrored on each instance ;

-  Striping: data are distributed over the different instances.

Adding an filesystem is as easy as adding an instance:

-  Single:

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilesystem -i <Filesystem Name> \
         -t Single \
         -c <Cache Directory Full Path> \
         -u <Full Threshold> \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -m <Mount Point> \
         <Instance Name>

-  Mirroring:

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilesystem -i <Filesystem Name> \
         -t Mirroring \
         -c <Cache Directory Full Path> \
         -u <Full Threshold> \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -m <Mount Point> \
         <Instance Name 1> ... <Instance Name N>

-  Striping:

   .. code:: bash

       $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilesystem -i <Filesystem Name> \
         -t Striping \
         -c <Cache Directory Full Path> \
         -u <Full Threshold> \
         -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
         -m <Mount Point> \
         <Instance Name 1> ... <Instance Name N>

The cloudgw user must own the cache directory.

Starting the Storage Manager
----------------------------

After completing the configuration, the Storage Manager can be started
as the *cloudgw* user with the following command:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager start

If you are working as root, you can use the following command to
launch Cloud Gateway under the *cloudgw* user:

.. code:: bash

    $ su - cloudgw -c '${INSTALL_PREFIX}/bin/CloudGatewayStorageManager start'

If you are working not as root but as a *sudoers* user, you can do
something like:

.. code:: bash

    $ sudo -u cloudgw ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager start

Mounting the filesystem
-----------------------

Using the mount point configuration, mounting the filesystem as
*cloudgw* is as simple as:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayMount \
      ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
      <Filesystem Name>

As previously seen, *root* or *sudoers* may instead want to to,
respectively:

.. code:: bash

    $ su - cloudgw -c '${INSTALL_PREFIX}/bin/CloudGatewayMount \
      ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
      <Filesystem Name>'

.. code:: bash

    $ sudo -u cloudgw ${INSTALL_PREFIX}/bin/CloudGatewayMount \
      ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml \
      <Filesystem Name>

Listing mounted filesystems
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The currently mounted filesystems list may be obtained at any time
using the *mount* command:

.. code:: bash

    $ mount
    [...]
    CloudGateway:MyFsId on $HOME/mymountpoint type fuse.cloudFUSE \
     (rw,nosuid,nodev,relatime,user_id=1001,group_id=1001, \
    default_permissions,allow_other)

The *df* command can also be used:

.. code:: bash

    $ df -h
    Filesystem            Size  Used Avail Use% Mounted on
    [...]
    CloudGateway:MyFsId   8.0E     0  8.0E   0% $HOME/mymountpoint

Unmouting a filesystem
----------------------

Unmounting a Cloud Gateway filesystem using its configuration file:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayUnmount \
      ${INSTALL_PREFIX}/etc/CloudGatewayMyMountPoint.xml \
      <Filesystem Name>

Unmounting a Cloud Gateway filesystem using its mount point, here
$HOME/mymountpoint:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayUnmount \
      $HOME/mymountpoint

As previously seen, *root* or *sudoers* may instead want to to,
respectively:

.. code:: bash

    $ su - cloudgw -c '${INSTALL_PREFIX}/bin/CloudGatewayUnmount \
      ${INSTALL_PREFIX}/etc/CloudGatewayMyMountPoint.xml \
      <Filesystem Name>'

.. code:: bash

    $ sudo -u cloudgw ${INSTALL_PREFIX}/bin/CloudGatewayUnmount \
      ${INSTALL_PREFIX}/etc/CloudGatewayMyMountPoint.xml \
      <Filesystem Name>

Stopping the Storage Manager
----------------------------

After all volumes have been unmounted, it is possible to stop the
Storage Manager with:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager stop

As previously seen, *root* or *sudoers* may instead want to to,
respectively:

.. code:: bash

    $ su - cloudgw -c '${INSTALL_PREFIX}/bin/CloudGatewayStorageManager stop'

.. code:: bash

    $ sudo -u cloudgw ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager stop

.. [8]
   More than one space are used in case of Striping or Mirroring

.. [9]
   Bucket in Amazon S3 terminology, container in Openstack
