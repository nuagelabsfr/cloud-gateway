Advanced configuration
======================

In the previous chapter, we have covered the basic usage of Cloud
Gateway. This one is going deeper into the advanced features of the
product, like the encryption and compression filters.

Filters
-------

Filters are a powerful tool allowing Cloud Gateway to transform data
on-the-fly while they are transferred to and from the storage providers.
Two filters are currently provided with Cloud Gateway 1.1.2, the
**encryption** filter and the **compression** filter.

Filters are applied to a specific instance, not to the whole filesystem.
This means that you can create a mirrored filesystem with a
non-encrypted instance, for example on a private cloud storage, and an
encrypted one using a public cloud provider.

Encryption
~~~~~~~~~~

One of the key goals of Cloud Gateway is to protect your files. This
means protecting them from becoming unreachables by using caching and
mirroring, but also protecting them from external snooping, by using
encryption at various levels.

In addition to protecting your data during the transfers to and from
storage providers with SSL and TLS, Cloud Gateway can use a filter to
encrypt your data before sending them to the storage provider,
transparently decrypting them when they are later retrieved. That way,
the storage provider himself has no way to access your data.

Two modes of operation are currently supported, Cipher Bloc Chaining
 [10]_ and CTR Integer Counter Mode  [11]_:

-  CBC is known to be vulnerable to padding-oracle attacks when not used
   properly, but this kind of attack is not practically feasable in the
   way it is used in Cloud Gateway. Moreover, Cloud Gateway uses a
   strong integrity check based on a Message Authentication Code  [12]_
   function, deterring any padding-oracle attack.

-  CTR is not vulnerable to this kind of attack and offer greater
   encryption speed because it allows blocks to be encrypted in
   parallel.

The exact list of supported ciphers can be found in the documentation
for the
*Configuration/Instances/Instance/Filters/Filter/Specifics/Cipher*
directive, but Cloud Gateway supports at least the following algorithms:

-  Advanced Encryption Standard  [13]_, a well-known NIST standard,
   supporting key sizes of 128, 192 and 256 bits ;

-  Camellia, a well-known japanese cipher supporting key sizes of 128,
   192 and 256 bits.

Please note that encryption is a CPU-consuming operation. For more
information, see section   on page .

Configuration
^^^^^^^^^^^^^

In order to add an encryption filter to an existing instance named
Instance1, using the *AES* cipher, with a 256-bits key based on the
*MyStrongPassphrase* password, a *SHA-256* digest and an iteration count
of 2000, the following command maye be used:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilterToInstance \
      -i Instance1 \
      -t Encryption \
      -c aes-256-ctr \
      -d sha256 \
      -k 2000 \
      -p MyStrongPassphrase \
      -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml

The complete list of supported ciphers and digests can be found below on
the description of, respectively, the
*Configuration/Instances/Instance/Filters/Filter/Specifics/Cipher* and
*Configuration/Instances/Instance/Filters/Filter/Specifics/Digest*
parameters.

Key derivation
^^^^^^^^^^^^^^

For each different file, a new key and initialization vector  [14]_ is
derivated from the user-supplied password. In order for this key and IV
to be different for each file, a salt is randomly generated for each
file at the beginning of the transfer and used in the key derivation
function. The exact processing is dependant on the
*Configuration/Instances/Instance/Filters/Filter/Specifics/Digest* and
*Configuration/Instances/Instance/Filters/Filter/Specifics/KeyIterationCount*
Storage Manager parameters. Nuage Labs advises that to you use a strong
digest, such as as *SHA-256*, and a key iteration count of at least
2000.

Compression
~~~~~~~~~~~

In order to speed up the transfer, save bandwidth and storage costs,
Cloud Gateway provides a compression filter based on the *deflate*
algorithm allowing on-the-fly compression of files. Depending on the
compression level and the data typology, the compression ratio can rise
up to 99%. Of course, an higher level of compression requires more CPU
time and uses more memory, so this level is configurable.

For more information on compression levels and cost, see section   on
page .

Configuration
^^^^^^^^^^^^^

In order to add a compression filter to an existing instance named
Instance1, using a compression level of 3 (best compression is 9,
fastest is 1), the following command maye be used:

.. code:: bash

    $ ${INSTALL_PREFIX}/bin/CloudGatewayAddFilterToInstance \
      -i Instance1 \
      -t Compression \
      -l 3 \
      -f ${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml

Restrictions
^^^^^^^^^^^^

Because of the inner concept of compression means that there is no way
to predict the exact size of compressed data from the original size,
Cloud Gateway’s compression filter requires that the storage provider
provides a way to send variable-length data without annoucing the final
size before-hand. Unfortunately, the **S3** API does not provide such an
ability. Therefore, **the compression filter is disabled for instances
using a S3 API**.

-----
 NFS
-----

Many customers want to export their Cloud Gateway filesystem over the
network, in order to be able to use it as a network attached storage.
The easiest way to do that is to export the filesystem over NFS, using
the Linux NFS kernel server.

Installing the system packages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The NFS kernel server package needs to be installed, and the exact
method differs from distribution. For aptitude-based distributions, this
is done with:

.. code:: bash

    $ aptitude install nfs-kernel-server portmap

For yum-based ones:

.. code:: bash

    $ yum install nfs-utils portmap

Editing the exports file
^^^^^^^^^^^^^^^^^^^^^^^^

The */etc/exports* file contains the list of all NFS exports, with the
options used for each one of them.

For the sake of this example, we will be exporting the Cloud Gateway
filesystem mounted on */home/cloudgw/mymountpoint*, and allow read-write
mode to all hosts in the *192.168.42.0/24* network.

.. code:: bash

    /home/cloudgw/mymountpoint \
      192.168.42.0/24(rw,no_subtree_check,fsid=42,insecure)

Users familiar with the /etc/exports syntax may be surprised to see the
rarely-used *fsid* option. Normally, filesystems provides the kernel
with a unique identifier, which is used as fsid by NFS. Due to a
limitation in the API Cloud Gateway is using, we have currently no way
of providing this identifier to the kernel. Therefore we have to
manually assign a unique numeric fsid for each Cloud Gateway volumes we
want to export over NFS. A simple positive integer, greater than zero
and unique for each export is sufficient.

The *rw* specifies a read-write filesystem, the *no\_subtree\_check* is
the default on most Linux versions and enhances stability, and finally
the *insecure* option allows requests originating on an Internet port
less than *IPPORT\_RESERVED* (1024). None of these last three options
are required for Cloud Gateway, but they are most of the time the ones
you will want to use.

(Re-)starting the services
^^^^^^^^^^^^^^^^^^^^^^^^^^

After editing the */etc/exports* file, you must start the corresponding
services:

.. code:: bash

    $ /etc/init.d/portmap start
    $ /etc/init.d/nfs-kernel-server start

If the services were already running, you can simply reload the
configuration file:

.. code:: bash

    $ exportfs -arv

.. [10]
   CBC

.. [11]
   CTR

.. [12]
   MAC

.. [13]
   AES

.. [14]
   IV
