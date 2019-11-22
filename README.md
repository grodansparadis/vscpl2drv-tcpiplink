# vscpl2drv-tcpiplink

<img src="https://vscp.org/images/logo.png" width="100">

    Available for: Linux, Windows
    Driver Linux: vscpl2drv-tcpiplink.so
    Driver Windows: vscpl2drv-tcpiplink.dll

A driver that send/receive events to/from a remote VSCP tcp/ip interface with automatic reconnection and security.



## Install the driver on Linux
You can install the driver using the debian package with

> sudo dpkg -i vscpl2drv-tcpiplink

the driver will be installed to /usr/lib

After installing the driver you need to add it to the vscpd.conf file (/etc/vscp/vscpd.conf). Se the *configuration* section above.

You also need to set up a configuration file for the driver. If you don't need to dynamically edit the content of this file a good and safe location for it is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration we recommend that you create the file in the */var/vscp/vscpl2drv-tcpiplink.so*

A sample configuration file is make available in */usr/share/vscpl2drv-tcpiplink.so* during installation.

## Install the driver on Windows
tbd

## How to build the driver on Linux
To build this driver you to clone the driver source

The build used **pandoc** for man-page generation so you should install it first with

```
sudo apt install pandoc
```

If you skip it the build will give you some errors (whish you can ignore if you don't care about the man page)


```
git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscpl2drv-tcpiplink.so.git
cd vscpl2drv-tcpiplink
./configure
make
make install
```

Default install folder is */usr/local/lib* when you build manually

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
<!-- Level II automation -->
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

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. If the **write** parameter is set to "true" the above location is a bad choice as the VSCP daemon will not be able to write to it. A better location is */var/lib/vscp/drivername/configure.xml* or some other writable location in this cased.

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
Set debug to "true" to get debug information written to syslog. This can be a valuable help if things does nor behave as expected.

##### write
If write is true the configuration file will be possible to save dynamically to disk. That is settings you do at runtime can be save to be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but dynamic saves there is not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is the folder */var/lib/vscp/drivername/configure.xml*. This folder and a default configuration is written here when the driver is installed.

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder.

##### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).

##### remote-host
Remote host to connect to. IP address or name.

##### remote-port
Port to connect to on remote host. Default is 9598.

##### remote-user
Username to login as on remote host.

##### remote-password
Password to use on remote host.

##### response-timeout
Response timout in milliseconds. Connection will be restarted if this expires.

##### filter
Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

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

