.. Cloud Gateway documentation master file, created by
   sphinx-quickstart on Thu Jun  8 16:49:42 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Cloud Gateway's documentation!
=========================================

Cloud Gateway is a software gateway turning any Cloud storage
service [1]_ into a local volume. No API integration is required, data
are stored on the Cloud, encrypted during transfers and can be
replicated between multiple Clouds.

Your Cloud storage area works as a local filesystem, which can be
exported to the network as a NAS [2]_ through standards protocols like
NFS [3]_ or CIFS [4]_, enabling the transparent use of all the Cloud
storage features without any modifications to exsiting applications or
any vendor lockup.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   features
   installation
   configuration
   advanced_usage
   advanced_configuration
   performances
   cli
   configuration_options

.. [1]
   Compatible with the Amazon S3 or Openstack API

.. [2]
   Network-Attached Storage

.. [3]
   Network File System

.. [4]
   Common Internet File System
