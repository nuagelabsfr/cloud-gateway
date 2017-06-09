Advanced usage
==============

Graceful stop and force stop
----------------------------

By default, the *CloudGatewayStorageManager stop* command does a
graceful stop, meaning that every component will gracefully finish all
their pending operations before exiting. These operations can be of
different types, including:

-  database queries ;

-  HTTP(S) transfers to or from the Cloud ;

-  Asynchronous input/output operations ;

-  signals handling.

It may happen that these operations take a bit of time to finish,
especially if there are some large files transfer in progress. In case
the administrator is not willing to wait for these operation to finish,
it is possible to issue a force stop command asking the Storage Manager
components to exit as soon as possible, even if some pending transfer
exist. Please note that in the case of segmented upload (also known as
multi-part upload), this may lead to some segments not being deleted
from the Cloud.

Issuing a force stop can be done with:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager force-stop

Graceful reload
---------------

Changes to the configuration can be applied without having to restart
the Storage Manager. The graceful reload command instructs the Storage
Manager to start new processes (Checker, Cleaner, Monitor, Server and
Syncer) with the new configuration, while the existing processes are
sent a graceful stop command, effectively finishing their pending
operations with the old configuration before exiting.

Issuing a reload is done with:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManager reload

Please note that there may be a very small delay between the moment the
old Server stops listening for queries from the FUSE component and the
moment the new Server begins listening. For this reason, it is possible
that mounted volumes experience a few I/O errors during the reload, even
if the underlying FUSE component tries very hard to detect and handle
the reload.

Testing a configuration file
----------------------------

In order to validate the correctness of a configuration file without
having to reload the Storage Manager or to unmount / mount a volume,
Cloud Gateway comes with two command-line utilities.

Testing the Storage Manager configuration file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Cloud Gateway Storage Manager configuration file can be tested
with the following command:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayStorageManagerConfigTest \
        ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml

If the configuration file is valid, the command outputs nothing and the
return value is set to zero. Otherwise, the command prints error
messages to the error stream and a non-zero code is returned.
