Features
--------

Flexible, on demand and cost-effective cloud storage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A key advantage in using Cloud storage is the unlimited physical storage
constraint. Your own local volume that could be mounted trough NFS
thanks to Cloud Gateway can bear as much data as you would like to
store. No saturation issue, no evolution issue, ttal flexibility, it’s
virtually infinite. And thanks to Cloud storage, you only pay for what
you use. Your storage costs become fully flexible. You don’t need to
invest in the acquisition of expensive storage solutions of several
Tera-Bytes which will be under-used. No more storage limit and your
storage costs is directly related to your need for expanded / reduced
storage.

No API, no development, no vendor lockup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using Cloud Gateway means there is no initial investment in API
integration. Moving to Cloud storage is only a few clicks away without
modifying the way your application is functioning in any way = Time &
Cost Efficiency.

The choice of Cloud storage providers is yours
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once connected via Cloud Gateway, no source code modification of your
software is required to integrate a proprietary API, therefore you keep
your freedom. Switching Cloud storage provider is up to you and only one
click away. You can also change back to a traditional local storage
avoiding any technical issue. You are totally independent and are able
to use competitive tension amongst providers to obtain best possible
terms on your data storage.

No lock-up through a proprietary API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Your own storage local volume is mounted through NFS (Network File
System) or CIFS (Common Internet File System) on your own platform as
though your storage is dealt with locally on your own network.
Re-internalisation of your data is possible at any time without any
technical or commercial difficulty.

Openness
^^^^^^^^

All data are retained in a fully transparent, accessible and documented
format. You will choose our products because they are the best out there
and not because you are stuck with them!

The Cloud Gateway concept is designed to release Cloud storage users
from proprietary API and offer a standardised interface POSIX compatible
which is accessible via standard and tested protocols such as FUSE, NFS
or CIFS. Bearing this in mind, our products do not include a proprietary
API and are fully based on standard protocols.

Our philosophy is to offer end users a maximum level of control on the
product through a number of fully flexible and configurable parameters:

-  Compression levels ;

-  Encryption algorithms ;

-  Optimal operation size (IO Block Size) ;

-  Timeouts duration at various levels (database access, HTTP(S)
   transfers etc.

All our configuration files are in XML format so as to be easily
readable by a person as well as easily handled via scripts or external
programs. These file formats are documented and are therefore
unsurprisingly standard.

Because we are aware our products and services are to be used in complex
environments, our products are designed to be able to interact with
various classic monitoring tools such as Munin or Nagios.

High availability
~~~~~~~~~~~~~~~~~

The Nuage Labs team is composed of highly trained engineers with a long
experience in complex architecture management with high availability
constraints. This is why our products are designed with the dual
objective of offering robustness, monitoring and fail-over systems in
order to guarantee service continuity at all times.

.. image:: images/cloud-gateway-redundancy.png
   :alt: High-Availability with Cloud Gateway

The active / passive mode from Cloud Gateway, linked with a mirroring
functionality from two separate Cloud storage providers offers an
architecture without a point of failure [5]_.

Integrity
~~~~~~~~~

Because we know your data are your most valuable asset, we have
integrated various encryption mechanisms within our solutions in order
to assess data integrity during data exchange with storage providers.
When your provider’s technology allow it, we check data integrity by
default as and when data are placed on the provider’s platform by
comparing the imprint before data are sent to the Cloud, with the one
recorded by the storage provider (usually MD5 format). We would also
typically check data integrity when recovering the file from the storage
provider. The way your data are stored is simple, transparent and
documented allowing you to repatriate them, should you choose to stop
using our service.

Confidentiality
~~~~~~~~~~~~~~~

Cloud Gateway can ensure files confidentiality at all times during
data transfers to the Cloud storage provider as well as during storage
through a strong specific encryption based on tried and tested
algorithms. Should you wish to, data transfers can be entirely performed
via HTTPS and files can be encrypted at a level satisfying your own
requirements:

-  AES 128 bits ;

-  AES 192 bits ;

-  AES 256 bits ;

-  Blowfish 128 bits ;

-  Camellia 128 bits ;

-  Camellia 192 bits ;

-  Camellia 256 bits.

Cloud Gateway supports the most secure standards of SSL/TLS to secure
your transfers, like TLS 1.0, 1.1 and 1.2, Perfect Forward Secrecy and
Elliptic Curves.

File encryption is always done on the basis of block chains (Cipher Bloc
Chaining or CTR Integer Counter Mode) with a salt and a unique and
randomly generated initialization vector (IV) in order to guarantee a
robust level of confidentiality. The encryption key is known only by
you. Nuage Labs does not have access to your data and should you
activate the data encryption, neither does the Cloud storage provider.

Efficiency
~~~~~~~~~~

A question often raised on data accessibility through the Cloud is
performance limitation while accessing files stored online. Cloud
Gateway solves this key issue, integrating a cache mechanism to its
solution. Although caches performance mostly depend on the equipment on
which they are deployed as well as the allocated size, our team is proud
to confirm that access performance are highly improved compared to a
direct Cloud storage (access to files not being dependent upon DNS or
HTTP(S) requests and not being constrained by bandwidth between your
application and the Cloud storage provider.

According to data storage typology, our compression system as
integrated to Cloud Gateway can reach factors close to 95%. The level of
compression can easily be configured balancing out the quantity of space
used at the storage provider level, data access time and CPU and memory
charge available on your platform.

In order to avoid classic bottlenecks, Cloud Gateway uses an
asynchronous event internal architecture with a low number of processes.
Each process is dedicated to its own task with a separate addressable
memory and is monitored by a parent process whose sole role is to ensure
other processes are correctly run.

The asynchronous architecture enables to avoid almost all drawbacks from
a number of processes such as:

-  thundering herd ;

-  lock contention ;

-  c10k problem.

The strict task slicing enables to limit modules and locks dependency
allowing to fully benefit from modern multi-cores architectures.

.. [5]
   Single Point of Failure, or SPoF
