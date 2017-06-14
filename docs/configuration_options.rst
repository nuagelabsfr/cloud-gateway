:tocdepth: 2

Configuration Options Reference
===============================

This section contains the documentation of all the parameters supported
by Cloud Gateway Storage Manager in its configuration file, located at
*${INSTALL_PREFIX}/etc/CloudGatewayConfiguration.xml*.

Configuration
-------------

-  Required: true

Root node of the configuration file.


Configuration/General
---------------------

-  Required: true

Contains the general parameters of the Cloud Gateway Storage Manager
process.

Configuration/General/ProvidersPath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: ${INSTALL_PREFIX}/lib/*

Path to the Storage Provider plugins directory.

Configuration/General/FiltersPath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: ${INSTALL_PREFIX}/lib/*

Path to the Storage Filter plugins directory.

Configuration/General/DBBackendsPath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: ${INSTALL_PREFIX}/lib/*

Path to the Database plugins directory.

Configuration/General/CommunicationSocket
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

Path to the Unix Socket used to communicate with the various Cloud
Gateway Fuse components. The Cloud Gateway Storage Manager process needs
creation, read and write access to this file.

Configuration/General/PidFile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

Path to the file where the Cloud Gateway Storage Manager process will
write its Process ID. Creation and write access to this file is needed
to the Storage Manager process.

Configuration/General/LogFile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  *Example: /tmp/CloudGatewayStorageManager.err*

Path to the file where the Cloud Gateway Storage Manager process will
write its log messages when needed. Creation and write access to this
file is needed to the Storage Manager process.

Configuration/General/MonitorInformationsPath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: /CloudGatewayStorageManagerMonitor.shared*

Path to the POSIX shared memory object used for the sharing of Storage
Providers status between the Cloud Gateway Storage Manager processes.
This path should be a string up to NAME\_MAX (i.e., 255) characters
consisting of an initial slash, followed by one or more characters, none
of which are slashes.

Configuration/General/StatsJSONFile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: /tmp/cgStats.json

-  *Example: /tmp/cgStats.json*

Path to the JSON file that the Stats process will write statistics
informations to.

Configuration/General/CleanerDBSlots
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 10

-  *Example: 10*

Maximum number of simultaneous database connections that the Cleaner
process will be able to obtain.

Configuration/General/CleanerDelay
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 60

-  *Example: 60*

Time in seconds between two passes of the cleaning process.

Configuration/General/SyncerDBSlots
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 20

-  *Example: 20*

Maximum number of simultaneous database connections that the Syncer
process will be able to obtain.

Configuration/General/SyncerDelay
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 5

-  *Example: 5*

Time in seconds between two passes of the syncing process.

Configuration/General/SyncerDirtynessDelay
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 10

-  *Example: 10*

Should match the CloudFuse Configuration/DirtynessDelay parameter.

Configuration/General/SyncerMaxDBObjectsPerCall
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 50

-  *Example: 50*

Maximum number of objects the Storage Manager Syncer process will
request in each DB call.

Configuration/General/Daemonize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Default: false

-  *Example: true*

Whether the Cloud Gateway Storage Manager should act as a daemon in the
background, as opposed to stay in the foreground.

Configuration/General/HTTPConnectionsCacheSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 0

-  *Example: 10*

Maximum amount of simultaneously open connections that each Storage
Manager process may cache. A value of 0 means no limit.

Configuration/General/HTTPMaxConnectionsByHost
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 0

-  *Example: 10*

Maximum amount of simultaneously open connections that each Storage
Manager process may open to a single host (based on the hostname). A
value of 0 means no limit.

Configuration/General/HTTPMaxConcurrentConnections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 0

-  *Example: 10*

Maximum amount of simultaneously open connections that each Storage
Manager process may have in total. A value of 0 means no limit.

Configuration/General/HTTPCABundleFile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: /etc/ssl/certs/ca-certificates.crt

-  *Example: /etc/ssl/certs/ca-certificates.crt*

Path to the file holding one or more certificates to verify the HTTP
SSL/TLS peers with. The special value ’None’ may be needed on some
system to disable the use of this file.

Configuration/General/HTTPCABundlePath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: /etc/ssl/certs/

-  *Example: /etc/ssl/certs/*

Path to the directory holding one or more certificates hash to verify
the HTTP SSL/TLS peers with. The special value ’None’ may be needed on
some system to disable the use of this directory.

Configuration/General/SyncerDumpHTTPStates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: false

-  *Example: true*

Dump Curl HTTP states during each Syncer run.

Configuration/Monitor
---------------------

-  Required: true

Contains the parameters related to the monitoring of Cloud Storage
Instances.

Configuration/Monitor/Delay
~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 20

-  *Example: 20*

Delay in seconds between two checks of the same Cloud Storage Instance.

Configuration/Monitor/FileSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 1048576

-  *Example: 1048576*

The size in bytes of the file sent to and retrieved from the Cloud
Storage Instance in order to check that everything is working fine.

Configuration/Monitor/FileId
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: CG\_STORAGE\_MANAGER\_MONITOR\_TEST\_FILE

-  *Example: CG\_STORAGE\_MANAGER\_MONITOR\_TEST\_FILE*

The identifier used at the Cloud Storage Provider for the test file.
This needs to be a valid file name for the Storage Provider API for each
monitored Instance.

Configuration/Monitor/FileTemplatePath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: /tmp

-  *Example: /tmp*

Path to the directory where the Monitor component may create temporary
files, with a size up to Configuration/Monitor/FileSize and a number of
temporary files up to the number of different Storage Instances. The
Cloud Gateway Storage Manager needs read and write access to this
directory.

Configuration/Monitor/FileDigest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: md5

-  Possible Values: md5, sha1, sha256, sha512

-  *Example: md5*

Algorithm used to compute the test file’s digest before and after
storage at the Storage Provider.

Configuration/DB
----------------

-  Required: true

Contains the parameters related to the database server.

Configuration/DB/Type
~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  Possible Values: PG

-  *Example: PG*

Database type.

Configuration/DB/Specifics/ConnectionString
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: PostgreSQL Database server

-  Required: true

-  *Example: host=127.0.0.1 port=5432 user=cloudgw
   password=PleaseChangeMe dbname=cloudgw*

A valid PostgreSQL connection string. If
Configuration/DB/Specifics/ReadOnlyConnectionString is set, this
connection string is used either only for write statements. Otherwise,
it is used for all statements.

Configuration/DB/Specifics/ReadOnlyConnectionString
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: PostgreSQL Database server

-  Required: false

-  *Example: host=127.0.0.1 port=5432 user=cloudgw
   password=PleaseChangeMe dbname=cloudgw*

A valid PostgreSQL connection string, used only for read-ony (aka
SELECT) statements. Write statements are done using the
Configuration/DB/Specifics/ConnectionString connection string.

Configuration/DB/Specifics/PoolSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: PostgreSQL Database server

-  Required: false

-  Default: 20

-  *Example: 20*

Number of connections in the connection pool.

Configuration/DB/Specifics/ConnectionRetry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: PostgreSQL Database server

-  Required: false

-  Default: 3

-  *Example: 3*

Number of connections retry attempts.

Configuration/Instances/Instance
--------------------------------

Configuration/Instances/Instance/Name
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: Openstack1*

Name of this instance.

Configuration/Instances/Instance/Provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  Possible Values: Amazon, Openstack

-  *Example: Openstack*

The instance’s storage provider.

Configuration/Instances/Instance/CheckObjectHash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an Amazon S3 or an Openstack Swift
   Provider

-  Required: false

-  Default: true

-  Possible Values: true, false

-  *Example: true*

Whether to check the hash returned by the provider, if any, when
uploading or downloading an object. This option has non negligeable
costs in terms of CPU processing time and memory usage, but is a very
effective way to protect file integrity.

Configuration/Instances/Instance/Specifics/HttpTimeout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: 0

-  Possible Values: 0-2147483647

-  *Example: 3600*

Maximum time in seconds allowed before cancelling an HTTP request.
Default is 0, which means no limit, except the underlying OS timeouts
for TCP connections.

Configuration/Instances/Instance/Specifics/HttpSSLCiphersSuite
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: ALL!EXPORT!EXPORT40!EXPORT56!aNULL!eNULL!LOW!DES

-  *Example: ALL!EXPORT!EXPORT40!EXPORT56!aNULL!eNULL!LOW!DES!RC4*

List of ciphers availables for TLS connections. More information can be
found at the following address:

https://www.openssl.org/docs/apps/ciphers.html

Configuration/Instances/Instance/Specifics/SSLClientCertificateFile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  *Example: ${INSTALL_PREFIX}/conf/ClientCertificates/cert1.pem*

The full path of a file containing a X.509 client certificate in PEM
format, which will be used for SSL/TLS client certificate authentication
if the server requires it. You will also need to configure the
SSLClientCertificateKeyFile directive.

Configuration/Instances/Instance/Specifics/SSLClientCertificateKeyFile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  *Example: ${INSTALL_PREFIX}/conf/ClientCertificates/cert1-key.pem*

The full path of a file containing the key in PEM format corresponding
to the X.509 client certificate specified with the
SSLClientCertificateFile directive. If the key is password-protected,
you will need to set the SSLClientCertificateKeyPassword directive.
Otherwise, the entire Storage Manager could be blocked, waiting for the
key to be entered.

Configuration/Instances/Instance/Specifics/SSLClientCertificateKeyPassword
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  *Example: ThisIsThePasswordLockingTheSSLClientCertificateKeyFile*

If the key present in the SSLClientCertificateKeyFile file is
password-protected, this directive should contain the password needed to
unlock the key, in plaintext.

Configuration/Instances/Instance/Specifics/MaxSingleUploadSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 1073741824

-  Possible Values: 10485760-5368709120

-  *Example: 1073741824*

The maximum size of a file to be uploaded in a single operation. File
larger than this size will be uploaded using the multipart/segmented API
of the provider when applicable.

Configuration/Instances/Instance/Specifics/MaxUploadSpeed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: 0

-  Possible Values: 0-2147483648

-  *Example: 1310720*

The maximum speed of a single upload, in bytes per second. If a transfer
exceeds this value on cumulative average, it will be paused to keep the
average rate below the value. 0 means unlimited.

Configuration/Instances/Instance/Specifics/MaxDownloadSpeed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: 0

-  Possible Values: 0-2147483648

-  *Example: 1310720*

The maximum speed of a single download, in bytes per second. If a
transfer exceeds this value on cumulative average, it will be paused to
keep the average rate below the value. 0 means unlimited.

Configuration/Instances/Instance/Specifics/LowSpeedLimit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: 0

-  Possible Values: 0-2147483648

-  *Example: 1280*

The transfer speed in bytes per second that the transfer should be below
during LowSpeedTime seconds in order to be considered too slow and
aborted. 0 means unlimited.

Configuration/Instances/Instance/Specifics/LowSpeedTime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: 0

-  Possible Values: 0-2147483648

-  *Example: 60*

The time in seconds that a transfer should be below the LowSpeedLimit in
order to be considered too slow and aborted. 0 means unlimited.

Configuration/Instances/Instance/Specifics/Verbose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: false

-  Possible Values: true, false

-  *Example: false*

Whether to log HTTP and HTTPS transaction. This option is useful for
debugging purpose, but must be used with caution. It will write a lot of
informations to disk, including confidential ones, may cause huge disk
I/Os and even fill the disk entirely.

Configuration/Instances/Instance/Specifics/ShowHTTPRequests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: false

-  Possible Values: true, false

-  *Example: false*

Whether to log HTTP and HTTPS requests and their result. This option is
useful for debugging purpose, and logs more readable, less verbose
informations that the Verbose option.

Configuration/Instances/Instance/Specifics/Disable100Continue
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: false

-  Possible Values: true, false

-  *Example: false*

Whether to disable the use of the Expect: 100-continue header, in case
the server does not support it.

Configuration/Instances/Instance/Specifics/DisableTCPFastOpen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: false

-  Possible Values: true, false

-  *Example: false*

Whether to disable the use of TCP Fast Open, in case the server does not
deal correctly with it.

Configuration/Instances/Instance/Specifics/HttpUserAgent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: CloudGateway (https://www.nuagelabs.fr)

-  *Example: CloudGateway (https://www.nuagelabs.fr)*

The HTTP User-Agent used for all HTTP requests made for this instances.

Configuration/Instances/Instance/Specifics/AllowInsecureHTTPS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using an HTTP-based storage provider, like
   Amazon S3 or Openstack Swift

-  Required: false

-  Default: false

-  *Example: false*

Whether to allow this instance to connect to a server providing an
invalid X.509 certificate. This can be useful for an internal, private
cloud without a valid certificate. This should not be enabled if you are
not really sure of what you are doing.

Configuration/Instances/Instance/Specifics/AccessKeyId
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Amazon S3 Provider

-  Required: true

The Access Key ID provided by the S3 provider.

Configuration/Instances/Instance/Specifics/SecretAccessKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Amazon S3 Provider

-  Required: true

The Secret Access Key provided by the S3 provider.

Configuration/Instances/Instance/Specifics/Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Amazon S3 Provider

-  Required: true

-  Possible Values: Any valid S3 Endpoint

-  *Example: s3-eu-west-1.amazonaws.com*

The S3 endpoint of this specific instance WITHOUT the bucket name. See
for example

http://docs.aws.amazon.com/general/latest/gr/rande.html#s3\_region

for more informations.

Configuration/Instances/Instance/Specifics/EndpointPath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the S3 Provider

-  Required: false

-  *Example: /s3/*

The path part of the uniform ressource locator of the S3 endpoint of
this specific instance.

Configuration/Instances/Instance/Specifics/EndpointPort
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Amazon S3 Provider

-  Required: true

-  Default: 80

-  *Example: 443*

-  Possible Values: 80, 443

The S3 endpoint TCP port of this specific instance. Use 80 for HTTP (Set
SecureTransaction to false) and 443 for HTTPS (Set SecureTransaction to
true).

Configuration/Instances/Instance/Specifics/SecureTransaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Amazon S3 Provider

-  Required: true

-  Default: false

-  Possible Values: true, false

-  *Example: true*

Whether to use Transport Layer Security (HTTPS) while connecting to the
S3 endpoint of this specific instance. Use false for HTTP (Set
EndpointPort to 80) and true for HTTPS (Set EndpointPort to 443). Please
be aware that this option has non negligeable costs in terms of CPU
processing time and memory usage. If you want to protect the
confidentiality of your files, we strongly advise to set this option to
true.

Configuration/Instances/Instance/Specifics/Bucket
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Amazon S3 Provider

-  Required: true

-  *Example: MyBucket*

The name of the S3 bucket to use for this instance.

Configuration/Instances/Instance/Specifics/IdentityVersion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  Required: false

-  Default: 2

-  Possible Values: 1, 2

-  *Example: 2*

The version of the identity method used by the provider. v1.0 is used by
Rackspace, v2.0, also known as Keystone, is used by most of the others
providers. v1.0 requires a username and an API access key, whereas v2.0
requires a username, password and a tenant id or a tenant name.

Configuration/Instances/Instance/Specifics/AuthenticationFormat
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider, with identity
   version 2

-  Required: false

-  Default: XML

-  Possible Values: XML, JSON

-  *Example: XML*

Experimental. Set the format used to send the credentials to the
Openstack Keystone server.

Configuration/Instances/Instance/Specifics/Username
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  Required: true

-  *Example: myUserName*

The user name provided by your Openstack provider.

Configuration/Instances/Instance/Specifics/Password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider, with identity
   version 2.

-  Required: false

-  *Example: myPassword*

The password provided by your Openstack provider.

Configuration/Instances/Instance/Specifics/TenantId
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider, with identity
   version 2

-  Required: false

-  *Example: myTenantId*

The tenant ID provided by your Openstack provider. Identity version 2
requires a valid tenant ID or a valid tenant name.

Configuration/Instances/Instance/Specifics/TenantName
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider, with identity
   version 2.

-  Required: false

-  *Example: myTenantName*

The tenant name provided by your Openstack provider. Identity version 2
requires a valid tenant ID or a valid tenant name.

Configuration/Instances/Instance/Specifics/APIAccessKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider, with identiy
   version 1

-  Required: false

-  *Example: Xoh2choh,/aeChoo3g*

The API Access Key provided by your Openstack provider. Required for
identity 1.0.

Configuration/Instances/Instance/Specifics/AuthenticationEndpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  *Example: https://lon.auth.api.rackspacecloud.com*

The Authentication Endpoint provided by your Openstack provider.

Configuration/Instances/Instance/Specifics/Container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  *Example: myContainer*

The name of the Openstack container to use for this instance.

Configuration/Instances/Instance/Specifics/PreferredRegion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  Required: false

-  *Example: Region1*

The object-store preferred region to use if the Openstack provider
provides more than one.

Configuration/Instances/Instance/Specifics/AuthenticationMaxLifetime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  Required: false

-  Default: 21600

-  *Example: 3600*

The maximum lifetime of an authentication token, in seconds.

Configuration/Instances/Instance/Specifics/AuthenticationTokenRecentDelay
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: An instance using the Openstack Provider

-  Required: false

-  Default: 60

-  *Example: 120*

An authentication error with a token older than this delay will trigger
a re-authentication.

Configuration/Instances/Instance/Filters/Filter/Type
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  Possible Values: Encryption, Compression

-  *Example: Encryption*

The name of the Cloud Storage Filter to apply before sending files to
the Cloud Storage Provider, and after retrieving them. This encryption
filter provides an acceptable level of confidentiality, as neither the
Cloud Storage Provider nor any intermediary will have access to a
unencrypted version of the file. The compression filter is not available
for S3 providers like Amazon, it will be ignored if it is set.

Configuration/Instances/Instance/Filters/Filter/Enabled
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  Possible Values: false, true

-  *Example: true*

Whether to active the corresponding filter or not. This option allows to
keep all the filter configuration options in the active configuration
file even if the filter is currently disabled.

Configuration/Instances/Instance/Filters/Filter/Specifics/Cipher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: Encryption filter

-  Required: true

-  Possible Values: aes-128-cbc, aes-192-cbc, aes-256-cbc, aes-128-ctr,
   aes-192-ctr, aes-256-ctr, bf-cbc, camellia-128-cbc, camellia-192-cbc,
   camellia-256-cbc

-  *Example: aes-128-ctr*

The symmetric cipher algorithm to use. The cipher algorithm used has a
huge impact in terms of processing time.

Configuration/Instances/Instance/Filters/Filter/Specifics/Digest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: Encryption filter

-  Required: true

-  Possible Values: md5, sha1, sha256, sha512

-  *Example: sha256*

The message digest to use to derive an encryption key (and an IV) based
on the user-submitted password (see
Configuration/Instances/Instance/Filters/Filter/Specifics/Password), the
key iteration count (see
Configuration/Instances/Instance/Filters/Filter/Specifics/KeyIterationCount),
and a randomly generated salt.

Configuration/Instances/Instance/Filters/Filter/Specifics/KeyIterationCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: Encryption filter

-  Required: true

-  *Example: 2000*

The count of key iterations used to derive an encryption key (and IV)
based on the user-submitted password (see
Configuration/Instances/Instance/Filters/Filter/Specifics/Password) and
a randomly generated salt. An higher Key Iteration Count parameter
increase the difficulty of performing a brute force attack against the
password, but equally slows down the key generation process.

Configuration/Instances/Instance/Filters/Filter/Specifics/Password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: Encryption filter

-  Required: true

-  *Example: PleasePleaseDontUseThis*

The password from which is derived the encryption key (and IV). See also
Configuration/Instances/Instance/Filters/Filter/Specifics/KeyIterationCount
and Configuration/Instances/Instance/Filters/Filter/Specifics/Digest.
Warning: if this password is lost, encrypted files will be lost forever.

Configuration/Instances/Instance/Filters/Filter/Specifics/Level
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Context: Compression filter

-  Required: true

-  Possible Values: 1-9

-  *Example: 1*

The compression level, from 1 to 9, 1 being the fastest and 9 the most
efficient, albeit the slowest and more memory consuming.

Configuration/FileSystems/FileSystem
------------------------------------

Configuration/FileSystems/FileSystem/Id
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: myFSID*

The name of this filesystem.

Configuration/FileSystems/FileSystem/Type
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: Single

-  Possible Values: Single, Mirroring, Striping

-  *Example: Mirroring*

The type of filesystem. A value other than single is only relevant for a
filesystem using two or more instances.

Configuration/FileSystems/FileSystem/CacheRoot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  *Example: ${INSTALL_PREFIX}/cache/*

An existing directory under which Cloud Gateway Storage Manager will
store cached files. This directory should be readable and writable, and
should have at least twice the size of the biggest file used on this
filesystem available.

Configuration/FileSystems/FileSystem/FullThreshold
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

-  Possible Values: 0-100

-  *Example: 10*

The minimum free space, in percent, that the filesystem containing the
CacheRoot directory should have in order not to be considered as
dangerously full. If this threshold is reached, the Cloud Gateway
Storage Manager Cleaner process will be executed in order to regain
space by deleting old unused files present in cache.

Configuration/FileSystems/FileSystem/IOBlockSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 4096

-  *Example: 4096*

The filesystem preferred I/O block size. Default depends on the
operating system page size.

Configuration/FileSystems/FileSystem/AutoExpunge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: false

-  *Example: true*

This option instructs the Storage Manager to expunge an entry from the
cache as soon as it has been synced to all the mirrored storage
providers.

Configuration/FileSystems/FileSystem/InodeDigestAlgorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: sha256

-  Possible Values: none, md5, ripemd160, sha1, sha256, sha512,
   whirlpool

-  *Example: sha256*

The filesystem inode digest algorithm. This digest is computed before
uploading the inode content, stored in the database and checked when the
inode content is downloaded.

Configuration/FileSystems/FileSystem/CleanMinFileSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 0

-  Possible Values: 1-18446744073709551615

-  *Example: 4096*

The minimum file size in bytes for an object to be considered by the
cache cleaning process. Default is 0.

Configuration/FileSystems/FileSystem/CleanMaxAccessOffset
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 86400

-  Possible Values: 60-18446744073709551615

-  *Example: 86400*

Only files that have been not been accessed for at least this value (in
seconds) might be cleaned. Default is 86400. A value under 60 will be
rounded up to 60.

Configuration/FileSystems/FileSystem/Instances/Instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

Instance name of one instance used by this filesystem. If more that one
instance is used by a filesystem, the filesystem type
(Configuration/FileSystems/FileSystem/Type) determines how each instance
will be used.

Configuration/FileSystems/FileSystem/MountPoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: true

The directory where the filesystem should be mounted.

Configuration/FileSystems/FileSystem/ConnectionsPoolSize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 10

-  *Example: 100*

The maximum number of cached connections to the storage manager.

Configuration/FileSystems/FileSystem/MaxConnectionIdleTime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 10

-  *Example: 60*

How long, in seconds, can a cached connection remain idle. 0 means
unlimited.

Configuration/FileSystems/FileSystem/MaxRequestsPerConnection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 1000

-  *Example: 10000*

The maximum number of requests that can be served over the same
connection. 0 means unlimited.

Configuration/FileSystems/FileSystem/RetryCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  *Example: 3*

-  Default: 3

How many times we reset a request and try again in case of error.

Configuration/FileSystems/FileSystem/DirtynessDelay
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 10

-  *Example: 10*

The FUSE component notify the Storage Manager about write() operation
done to a file, at most every dirtyness delay seconds.

Configuration/FileSystems/FileSystem/NameMax
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 255

-  *Example: 255*

The maximum length of a pathname component, 0 means unlimited.

Configuration/FileSystems/FileSystem/PathMax
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 1024

-  *Example: 1024*

The maximum length of a path, 0 means unlimited.

Configuration/FileSystems/FileSystem/DirIndexLimit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Required: false

-  Default: 10000

-  *Example: 10000*

Store an in-memory hash table to list entries in directory to have
better performance when there is more than DirIndexLimit entries.
