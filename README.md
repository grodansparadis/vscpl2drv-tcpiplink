# vscpl2drv-tcpiplink

<img src="https://vscp.org/images/logo.png" width="100">

    Available for: Linux, Windows
    Driver Linux: vscpl2drv-tcpiplink.so
    Driver Windows: vscpl2drv-tcpiplink.dll

The tcp/ip driver can send/receive events to/from a remote VSCP tcp/ip interface with automatic reconnection and security. The remote node is notmally a high level VSCP hardware device ir a VSCP daemon.

The driver will try to hold a connection open even if the remote node disconnects. This makes it possible to replace a node or take it down for maintenance and still have the link online again as soon as the node is powered up. 

Thje tcp/ip link protocol is described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_tcpiplink).

## Install the driver on Linux
You can install the driver using the debian package with

> sudo apt install ./vscpl2drv-tcpiplink.deb

the driver will be installed to /usr/lib

After installing the driver you need to add it to the vscpd.conf file (/etc/vscp/vscpd.conf). Se the *configuration* section below.

You also need to set up a configuration file for the driver. If you don't need to dynamically edit the content of this file a good and safe location for this is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration we recommend that you create the file in the */var/vscp/vscpl2drv-tcpiplink.so*

A sample configuration file is make available in */usr/share/vscpl2drv-tcpiplink.so* after installation.

## Install the driver on Windows
tbd

## How to build the driver on Linux
To build this driver you to clone the driver source

The build used **pandoc** for man-page generation so you should install it first with

```
sudo apt install pandoc
```

If you skip it the build will give you some errors (which you can ignore if you don't care about the man page)


```
git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscpl2drv-tcpiplink.so.git
cd vscpl2drv-tcpiplink
./configure
make
make install
```

Default install folder when you build from source is */usr/local/lib*. You can change this with the --prefix option in the configure step. For example *--prefix /usr* to install to */usr/lib* as the debian install

You need build-essentials and git installed on your system

>sudo apt update && sudo apt -y upgrade
>sudo apt install build-essential git

## How to build the driver on Windows
tbd

## Configuration

### Linux

#### VSCP daemon driver config

The VSCP daemon configuration is (normally) located at */etc/vscp/vscpd.conf*. To use the vscpl2drv-tcpiplink.so driver there must be an entry in the

```
> <level2driver enable="true">
```

section on the following format

```xml
<!-- Level II TCP/IP link -->
<driver enable="true"
    name="link"
    path-driver="/usr/lib/vscpl2drv-tcpiplink.so"
    path-config="/var/lib/vscpl2drv-tcpiplink/drv.conf"
    guid="FF:FF:FF:FF:FF:FF:FF:FC:88:99:AA:BB:CC:DD:EE:FF"
</driver>
```

##### enable
Set enable to "true" if the driver should be loaded.

##### name
This is the name of the driver. Used when referring to it in different interfaces.

##### path
This is the path to the driver. If you install from a Debian package this will be */usr/bin/vscpl2drv-tcpiplink.so* and if you build and install the driver yourself it will be */usr/local/bin/vscpl2drv-tcpiplink.so* or a custom location if you configured that.

##### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).

#### vscpl2drv-tcpiplink driver config

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. If the **write** parameter is set to "true" the above location is a bad choice as the VSCP daemon will not be able to write to it. A better location is */var/lib/vscp/drivername/configure.xml* or some other writable location.

The configuration file have the following format

```xml
<?xml version = "1.0" encoding = "UTF-8" ?>
    <!-- Version 0.0.1    2019-11-05   -->
    <config debug="true|false"
            write="true|false" 
            remote-host="hostname or ip-address" 
            remote_port="9598 or other port" 
            remote_user="user on remote host"
            remote_password="password on remote host" 
            response-timeout="0"
            filter="incoming-filter"
            mask="incoming-mask" />
```

##### debug
Set debug to "true" to get debug information written to syslog. This can be a valuable help if things does not behave as expected.

##### write
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivername/configure.xml*. This folder is created and a default configuration is written here when the driver is installed.

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder.

##### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).

##### remote-host
Remote VSCP tcp/ip link interface host to connect to. IP address or name.

##### remote-port
Port to connect to on VSCP tcp/ip link interface on remote host. Default is 9598.

##### remote-user
Username to login as on VSCP tcp/ip link interface on remote host.

##### remote-password
Password to use on VSCP tcp/ip link interface remote host.

##### response-timeout
Response timeout in milliseconds. Connection will be restarted if this expires.

##### filter
Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

##### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

### Windows
See information from Linux. The only difference is the disk location from where configuration data is fetched.

## Using the vscpl2drv-tcpiplink driver

