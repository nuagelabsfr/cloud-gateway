Installation
============

There is currently only one way to install Cloud Gateway on a server:

-  compiling it from source.

Technical requirements
----------------------

For the machine (either virtual or bare-metal) on which Cloud Gateway
is to be deployed, the following requirements shall be met:

-  a Linux 64 bits kernel >= 2.6.32 ;

-  a Bash shell >= 3.0 ;

-  a PostgreSQL server >= 9.1  [6]_ ;

-  a FUSE module [7]_.

At this time, Cloud Gateway has been successfully tested on the
following Linux versions:

-  Debian 7.0 (x86\_64) (Wheezy) ;

-  Debian 8.0 (x86\_64) (Jessie) ;

-  Ubuntu Server 12.04 (x86\_64) (LTS) ;

-  Ubuntu Server 13.04 (x86\_64) ;

-  Ubuntu Server 13.10 (x86\_64) ;

-  Ubuntu Server 14.04 (x86\_64) (TLS) ;

-  openSUSE 12.3 (x86\_64) (Dartmouth) ;

-  openSUSE 13.1 (x86\_64) (Bottle) ;

-  SUSE Linux Enterprise Server 11.2 (x86\_64) ;

-  CentOS 6.4 (x86\_64).

Compilation
-----------

You can find the source on github :
https://github.com/nuagelabsfr/cloud-gateway. Please follow the README
instructions you will find in the repository.

Cloud Gateway User
------------------

Because Cloud Gateway does not need any security privileges to run,
Nuage Labs strongly advises to use a dedicated system user instead of
running Cloud Gateway as *root*.

For that reason, the Debian package creates a new user named *cloudgw*
if it does not exist yet. This user owns the Cloud Gateway files, and it
is under its identity that Cloud Gateway should be run.

.. [6]
   the PostgreSQL server can be installed on an other host, or even on a
   cluster of hosts for maximum performance

.. [7]
   File System In Userspace, a kernel component available in all modern
   distributions
