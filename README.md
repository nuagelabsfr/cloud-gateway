Cloud Gateway
=============

Cloud Gateway's goal is to make it easy to store files in an object-based
storage like Amazon S3 or Openstack Swift, while retaining the features
of a POSIX filesystem.

Cloud Gateway is developed since 2011 by Nuage Labs SAS, and has been
released as an Open Source Software in 2017 under the AGPLv3 license.

For Full documentation see docs/README.md.

Prerequistes
------------

Install prerequistes:
```
sudo apt-get install build-essential bzip2 gzip git libreadline-dev libpq-dev postgresql-server-dev-all libcurl4-openssl-dev libnl-3-dev libnl-genl-3-dev libnl-nf-3-dev libnl-route-3-dev libxml2-dev libevent-dev libfuse-dev libjson-c-dev
wget https://bitbucket.org/rgacogne/libevaio/get/libevaio_0_4.tar.bz2
tar xjf libevaio_0_4.tar.bz2
cd rgacogne-libevaio-36c968b3ad5f
mkdir build && cd build && cmake ../ && make
sudo make install
```

Compilation
-----------

Cloud Gateway's build is based on `cmake`.

Get cloudgw:

```
git clone https://github.com/nuagelabsfr/cloud-gateway.git
cd cloudgw
```

To build in debug mode, you can simply do:

```
mkdir build && cd build && cmake ../src && make
```

In order to do a release build:
```
mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local ../src && make
```

Install
-------

```
sudo apt-get install postgresql fuse

sudo sed -i 's,#user_allow_other,user_allow_other,' /etc/fuse.conf

sudo make install
sudo cp /usr/local/etc/CloudGatewayConfiguration.xml.sample /usr/local/etc/CloudGatewayConfiguration.xml

sudo bash /usr/local/share/cloudgateway/bin/create_db_user_as_root.sh

sudo groupadd cloudgw
sudo useradd -g cloudgw -m --home-dir /home/cloudgw cloudgw

sudo chgrp cloudgw /usr/local/etc/CloudGatewayConfiguration.xml
sudo chmod g+rw /usr/local/etc/CloudGatewayConfiguration.xml

sudo mkdir -p /usr/local/run/cloudgateway
sudo chgrp cloudgw /usr/local/run/cloudgateway
sudo chmod g+w /usr/local/run/cloudgateway
```

Configuration
-------------

0. For more options see the documentation (docs/ReferenceManual)

1. Add a Cloud Storage provider instance (here with OpenstackSwift Identity v2 with a TenantName) :

```
CloudGatewayAddInstance -n <Instance Name> \
            -P Openstack \
            -f /usr/local/etc/CloudGatewayConfiguration.xml \
            -i 2 -A <Authentication Endpoint> -c <Container Name> \
            -u <Username> -p <Password> -T <Tenant Name>
```

Caution: Note that the container / bucket should exist before the Storage Manager is started.
Caution: Please take care of the fact that the Openstack Authentication Endpoint URL does not contain the final /v1.0/, /v1.1/ or /v2.0/ part that some providers mention in their documentation, as it is automatically appended by Cloud Gateway.

2. Add a filesystem using this provider
```
CloudGatewayAddFilesystem -i <Filesystem Name> \
        -t Single \
        -c <Cache Directory Full Path> \
        -u <Full Threshold> \
        -f /usr/local/etc/CloudGatewayConfiguration.xml \
	-m <Mount Point> \
        <Instance Name>
```

Run CloudGateway without systemd
--------------------------------

1. Launch CloudGateway
```
sudo -u cloudgw /usr/local/bin/CloudGatewayStorageManager start
```

2. Mount the Filesystem
```
sudo mkdir <Mount Point>
sudo chown clougw <Mount Point>
sudo -u cloudgw /usr/local/bin/CloudGatewayMount <Filesystem Name> /usr/local/etc/CloudGatewayConfiguration.xml &
```

Run CloudGateway with systemd
--------------------------------

1. Copy systemd service files
```
sudo cp /usr/local/share/cloudgateway/resources/cloudgatewaymount\@.service /etc/systemd/system
sudo cp /usr/local/share/cloudgateway/resources/cloudgateway.service /etc/systemd/system
```

2. Reload systemd
```
sudo systemctl daemon-reload
```

3. Start CloudGateway
```
sudo systemctl start cloudgateway
```

4. Mount the Filesystem
```
sudo systemctl start cloudgatewaymount@<Filesystem Name>
```
