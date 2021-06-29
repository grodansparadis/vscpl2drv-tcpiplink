# vscpl2drv-tcpiplink

<img src="https://vscp.org/images/logo.png" width="100">

    Available for: Linux, Windows
    Driver Linux: vscpl2drv-tcpiplink.so
    Driver Windows: vscpl2drv-tcpiplink.dll

The VSCP tcp/ip link driver can send/receive events to/from a remote VSCP tcp/ip link interface with automatic reconnection and security. The remote node is normally a high level VSCP hardware device or a VSCP daemon, either a pre version 15 with built in tcp/ip interface or a version >=15 with the [vscpl2drv-tcpipsrv](https://github.com/grodansparadis/vscpl2drv-tcpipsrv) driver installed.

The driver will try to hold a connection open even if the remote node disconnects. This makes it possible to replace a node or take it down for maintenance and still have the link online again as soon as the node is powered up. 

The VSCP tcp/ip link protocol is described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_tcpiplink).

## Install the driver on Linux
You can find binary installation files [here](https://github.com/grodansparadis/vscpl2drv-tcpiplink/releases)

You install the driver using the debian package with

> sudo apt install ./vscpl2drv-tcpiplink_15.0.0.deb

the driver will be installed to the folder _/var/lib/vscp/drivers/level2/_. 

After installing the driver you need to add configuration information for it to the vscpd.conf file (_/etc/vscp/vscpd.json_). Se the *configuration* section below.

You also need to set up the configuration file for the driver. If you don't need to dynamically edit the content of this file a good and safe location for it is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration (**write** enabled) we recommend that you create the file in the _/var/lib/vscp/_ folder or any location you find to be convenient.

A sample configuration file is available in _/usr/share/vscp/drivers/level2/vscpl2drv-tcpiplink_ folder after installation. The sample configuration file is named tcpiplink.json.

## Install the driver on Windows
tbd

## How to build the driver on Linux

You need _build-essentials_ and _git_ installed on your system

```bash
sudo apt update && sudo apt -y upgrade
sudo apt install build-essential git
```

To build this driver you to clone the driver source

```bash
git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscpl2drv-tcpiplink.git
```

You also need to have the vscp main repository checkout at the same location as you checkout the driver. Do this with

```bash
git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscp.git
```

The build used **pandoc** for man-page generation so you want the man pages you should install it first with

```
sudo apt install pandoc
```

If you skip it the build will give you some errors (which you can ignore if you don't care about the man page)

Now go into the repository and build the driver

```
cd vscpl2drv-tcpiplink
mkdir build
cd build
cmake ..
make
sudo make install
```

If uou want to generate binary packages issue

```bash
sudo cpack
```

Default install folder when you build from source is */var/lib/vscp/drivers/level2*. You can change this with the --prefix option in the make install step. For example 

```
make DESTDIR==/usr/local install
```

to install to */usr/local/var/lib/vscp/drivers/level2*.


## How to build the driver on Windows
tbd

## Configuration

### Linux

#### VSCP daemon driver config

The VSCP daemon configuration file is (normally) located at */etc/vscp/vscpd.json* (For the curious: [VSCP daemon full sample config file for Linux](https://github.com/grodansparadis/vscp/blob/master/resources/linux/vscpd.json)). To use the vscpl2drv-tcpiplink.so driver there must be an entry in the drivers level2 section

```json
"drivers" : {
  "level2" : [
```

with the following format

```json
{
  "enable" : true,
  "name" : "tcpiplink",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-tcpiplink.so",
  "path-config" : "/etc/vscp/tcpiplink.json",
  "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:99:99:00:00:00:00:00:00",

  "mqtt": {
    "bind": "",
    "host": "test.mosquitto.org",
    "port": 1883,
    "mqtt-options": {
      "tcp-nodelay": true,
      "protocol-version": 311,
      "receive-maximum": 20,
      "send-maximum": 20,
      "ssl-ctx-with-defaults": 0,
      "tls-ocsp-required": 0,
      "tls-use-os-certs": 0
    },
    "user": "vscp",
    "password": "secret",
    "clientid": "the-vscp-daemon",
    "publish-format": "json",
    "subscribe-format": "auto",
    "qos": 1,
    "bcleansession": false,
    "bretain": false,
    "keepalive": 60,
    "bjsonmeasurementblock": true,
    "topic-daemon-base": "vscp-daemon/{{guid}}/",
    "topic-drivers": "drivers",
    "topic-discovery": "discovery",
    "reconnect": {
      "delay": 2,
      "delay-max": 10,
      "exponential-backoff": false
    },
    "tls": {
      "cafile": "",
      "capath": "",
      "certfile": "",
      "keyfile": "",
      "pwkeyfile": "",
      "no-hostname-checking": true,
      "cert-reqs": 0,
      "version": "",
      "ciphers": "",
      "psk": "",
      "psk-identity": ""
    },
    "will": {
      "topic": "vscp-daemon/{{srvguid}}/will",
      "qos": 1,
      "retain": true,
      "payload": "VSCP Daemon is down"
    },
    "subscribe" : [
      {
        "topic": "remote-vscp/{{guid}}/#",
        "qos": 0,
        "v5-options": 0,
        "format": "auto"
      }
    ],
    "publish" : [
      {
        "topic": "vscp/{{guid}}/{{class}}/{{type}}/{{nodeid}}",
        "qos": 1,
        "retain": false,
        "format": "json"
      }
    ]
  }
}
```

##### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

##### name
This is the name of the driver. Used when referring to it in different interfaces.

##### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-tcpiplink.so*.

##### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/tcpiplink.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP tcp/ip link interface. Never make it writable at this location.

##### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

##### mqtt
See the [VSCP configuration documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) for info about this section. It is common for all drivers.

#### vscpl2drv-tcpiplink driver config

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. If the **write** parameter is set to "true" the above location is a bad choice as the VSCP daemon will not be able to write to it. A better location is */var/lib/vscp/drivername/configure-name.json* or some other writable location.

The configuration file have the following format

```json
{
  "debug" : false,
  "write" : false,
  "key-file": "/var/vscp/vscp.key",
  "encryption" : "none|aes128|aes192|aes256",
  "logging": {
    "console-enable": true,
    "console-level": "trace",
    "console-pattern": "[vcpl2drv-tcpiplink %c] [%^%l%$] %v",
    "file-enable": true,
    "file-log-level": "debug",
    "file-log-path" : "/var/log/vscp/vscpl1drv-tcpiplink.log",
    "file-log-pattern": "[vcpl2drv-tcpiplink %c] [%^%l%$] %v",
    "file-log-max-size": 50000,
    "file-log-max-files": 7
  }, 
  "remote" : {
    "host" : "192.168.1.7",
    "port" : 9598,
    "user" : "admin",
    "password" : "secret",
    "response-timeout": 0
  },
  "tls": {
    "certificate" : "/srv/vscp/certs/tcpip_server.pem",
    "certificate-chain" : "",
    "verify-peer" : false,
    "ca-path" : "",
    "ca-file" : "",
    "verify-depth" : 9,
    "default-verify-paths" : true,
    "cipher-list" : "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256",
    "protocol-version" : 3,
    "ssl_cache_timeout": -1,
    "short-trust" : false
  },
  "filter" : {
    "in-filter" : "incoming filter on string form",
    "in-mask" : "incoming mask on string form",
    "out-filter" : "outgoing filter on string form",
    "out-mask" : "outgoing mask on string form"
  }
}
```

##### debug
Set debug to _true_ to get debug information written to the log file. This can be a valuable help if things does not behave as expected.

##### write
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivers/level2/configure.json*. A default configuration file is written to [/usr/share/vscp/drivers/level2/vscpl2drv-tcpiplink](/usr/share/vscp/drivers/level2/vscpl2drv-tcpiplink) when the driver is installed.

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder is a good choice.

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

