# CyberX Proxy Cookbook

Author: Ryan Kerr (ryan.kerr@queensu.ca)

## Proxy Settings

IPv4: `10.121.10.81/24`

IPv6: `fd00:a:7900:a::51/64`


## [Apache Traffic Server](https://trafficserver.apache.org/) on OpenSUSE 15.3

### Getting Started
After setting up OpenSUSE, the following packages should be installed with `sudo zypper in`:
- git
- curl

### Installing ATS
ATS does not appear to be available in the OpenSUSE repositories, but can be compiled from source by following the following instructions modified from [the docs](https://docs.trafficserver.apache.org/en/latest/getting-started/index.en.html#installing-from-source-code).

Install the following packages with `sudo zypper in`:
- libopenssl-devel
- zlib-devel
- pcre-devel
- libcap-devel
- make
- flex
- hwloc
- lua
- gcc
- gcc-c++
- libtool
- pkgconfig

The repository can be fetched and made into the working directory.

```
git clone https://github.com/apache/trafficserver
cd trafficserver
```

To select an alternate version, such as `9.2.x`, use the following command:

```
git fetch
git switch 9.2.x
```

The following steps will compile and install ATS in `/opt/ts`:

```
autoreconf -if
./configure --prefix=/opt/ts --enable-tproxy --enable-posix-cap
make
make test
make install
```

The installation can be verified with the following line. This step appears to fail when using the `clang` compiler.

```
sudo /opt/ts/bin/traffic_server -R 1
```

## Starting trafficserver
Traffic server is not set up for OpenSUSE 15 and relies on SysV scripts. Executing the following commands will ensure compatibility:

```
zypper in sysvinit-tools
touch /etc/SuSE-release
```

To use trafficserver with systemd, the following unit file (`ats.service`) can be written to `/etc/systemd/system`:

```
[Unit]
Description=Apache Traffic Server
After=network-pre.target

[Service]
Type=forking
ExecStartPre=/opt/fw/start.sh
ExecStart=/opt/ts/bin/trafficserver start
#ExecStartPost=/opt/fw/clear_bypass.sh
PIDFile=/opt/ts/var/trafficserver/server.lock
ExecStop=/opt/ts/bin/trafficserver stop
ExecStopPost=/opt/fw/bypass.sh

[Install]
WantedBy=multi-user.target
```

It should now be possible to start the server at boot using `systemctl enable ats`.

When started with systemd (at boot or explicitly `systemctl start ats`), this unit file will set the necessary firewall rules for proxying. In the event of an error, systemd will trigger the bypass script, allowing web traffic to continue flowing without going through the potentially failed proxy.

Note that the bypass rules are cleared after startup in case the firewall start script starts with the bypass rules set as a failsafe.

## Setting up a dedicated trafficserver user
ATS requires read access to the CA certificate and keys, however, ATS uses the `nobody` account by default. To provide access to ATS specifically, it is probably a good idea to create a new user.

```
useradd -UMrs /sbin/nologin ts
```

To tell ATS to use this new user, it must be specified in `records.config`:

```
CONFIG proxy.config.admin.user_id STRING ts
```

## Setting up networking and iptables routing
OpenSUSE uses the firewalld front-end, however, all manuals and reference guides use iptables directly. The default firewalld configuration appears to block icmp forwarding, resulting in an ICMP host unreachable. The rest of this cookbook assumes firewalld is disabled.

```
systemd disable --now firewalld
```

Networking can be set up using the `yast` interface. The test environment has 2 interfaces `eth0`, for accessing the machine, and `eth1`, for proxying traffic. Note that IPv4 and v6 forwarding must be enabled in the `Routing` tab.

The following script, based on the example doc, will intercept packets and pass them along to the proxy port.

```
#!/bin/bash

iface=eth0
v4="10.121.10.81"
v6="fd00:a:7900:a::51"

# /etc/iproute2/rt_tables: Arbitrary table number
rt_table=64

intercept() {
	local command=$1
	local address=$2
	local origin_port=$3
	local proxy_port=$4

	# Pass intercepted traffic to the local proxy port
	$command -t mangle -A PREROUTING -i $iface \
		! -s $address ! -d $address -p tcp -m tcp --dport $origin_port \
		-j TPROXY --on-ip 0.0.0.0 --on-port $proxy_port --tproxy-mark 1/1
}

intercept iptables  $v4 80  8080
intercept ip6tables $v6 80  8080
intercept iptables  $v4 443 8443
intercept ip6tables $v6 443 8443

ip rule add fwmark 1/1 table $rt_table
ip route add local 0.0.0.0/0 dev lo table $rt_table
```

The above script is a minimal example and has been since modified to be a helper script for initializing the firewall and bypassing the proxy if required. These scripts are included in the `fw` directory and are hard-coded to be placed in the `/opt/fw` directory.


## Forward HTTP Proxy
Setting up a basic HTTP interception proxy is possible by using the `tr-in` option in the server port specification within `records.config`. Since the OpenBSD router is set to only route web traffic from the proxy to external networks, the `ip-out` option acts as a NAT by not spoofing the requesting address.

```
CONFIG proxy.config.http.server_ports STRING 8080:tr-in:ip-out=10.121.10.81
CONFIG proxy.config.http.max_proxy_cycles INT 1
CONFIG proxy.config.url_remap.remap_required INT 0
```

For some reason, leaving `max_proxy_cycles` as-is tends to result in certain sites being mis-identified as a direct cycle and not being reachable. Setting this to 1 disables the cycle check and subverts this issues.

URL re-mapping is used for reverse proxying and is set as required by default. Since ATS is being used as a forward proxy, this requirement must be disabled.

For IPv6 configurations, the `ipv6` option must be specified and the address must be enclosed in square brackets.

## Forward HTTPS Proxy
HTTPS ports are specified in the same way as HTTP ports, but with the added `ssl` option. By default, HTTPS ports support both HTTP 1.0 and 2.0.

In order for the proxy to intercept HTTPS requests, the server must be able to generate fake certificates for each of the websites requested by the clients. To achieve this, trafficserver requires a self-signed certificate authority.

```
# /opt/ts/etc/ssl
openssl req -x509 -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt

# Serial file
echo -e '1\n' > ca.srl
```

This certificate must be readable by the user running trafficserver.

The `-nodes` (no DES) flag may be optionally specified to remove password protection for the certificate. This seems to interfere with the certifier plugin (below), but may be circumvented by added an entry to the `ssl_multicert.config`. Unfortunately, this means the password has to be accessible somewhere on the system or specified at runtime.

If the `ca.crt` is not signed by a certificate authority in the trusted certificate list of the clients, this `ca.crt` must be distributed and manually added to the list.

ATS doesn't appear to generate spoofed certificates by default and relies on a plugin, certifier, to do so. This plugin can be enabled and configured in `plugin.config` as follows:

```
certifier.so --sign-cert /opt/ts/etc/ssl/ca.crt --sign-key /opt/ts/etc/ssl/ca.key --sign-serial /opt/ts/etc/ssl/ca.srl --store /opt/ts/etc/ssl/certs --max 1000
```

It should be noted that the `store` and `max` parameters are required. Omitting these options will result in a segmentation fault with no helpful error message.

The following options can be added to `records.config` to enforce verification of remote HTTPS servers:

```
CONFIG proxy.config.ssl.client.verify.server.policy STRING ENFORCED
CONFIG proxy.config.ssl.client.CA.cert.path STRING /etc/ssl/certs
CONFIG proxy.config.ssl.CA.cert.path STRING /etc/ssl/certs
```

## Removing Headers
By default, ATS adds forward and server headers that expose the requesting client and server version. The following options can be set to prevent these headers from being included.

```
CONFIG proxy.config.http.insert_client_ip INT 0
CONFIG proxy.config.http.insert_squid_x_forwarded_for INT 0
CONFIG proxy.config.http.response_server_enable INT 0
CONFIG proxy.config.http.insert_request_via_str INT 0
CONFIG proxy.config.http.insert_response_via_str INT 0
CONFIG proxy.config.http.insert_age_in_response INT 0
```

## Hiding User Agents
This option could potentially come in useful, but may break compatibility with some websites.

```
CONFIG proxy.config.http.global_user_agent_header STRING ""
```

## Enabling Verbose Output

```
CONFIG proxy.config.diags.output.alert STRING E
CONFIG proxy.config.diags.output.emergency STRING E
CONFIG proxy.config.diags.output.error STRING E
CONFIG proxy.config.diags.output.fatal STRING E
CONFIG proxy.config.diags.output.note STRING E
CONFIG proxy.config.diags.output.status STRING E
CONFIG proxy.config.diags.output.warning STRING E
```


## [Squid v4.17](http://www.squid-cache.org) on OpenBSD 6.9

### Proxy Banner (/etc/issue)
```
      _/_/_/                      _/        _/
   _/          _/_/_/  _/    _/        _/_/_/
    _/_/    _/    _/  _/    _/  _/  _/    _/
       _/  _/    _/  _/    _/  _/  _/    _/
_/_/_/      _/_/_/    _/_/_/  _/    _/_/_/
               _/
              _/
```

### Getting Started
After setting up OpenSUSE, the following packages should be installed with `pkg_add`:
- git
- vim (or neovim)


### Network Configuration (/etc/hostname.em1)

```
inet 10.121.10.81/24
inet6 fd00:a:7900:a::51/64
```

### Routing Configuration (/etc/pf.conf)

```
iface = "em1"
logging = "log(all)"

# Divert intercepted HTTP (TCP 80) traffic to Squid
pass in $logging quick on $iface proto tcp \
	from ! $iface to ! $iface port 80 \
	divert-to lo0 port 3129

# Divert intercepted HTTPS (TCP 443) traffic to Squid
pass in $logging quick on $iface proto tcp \
	from ! $iface to ! $iface port 443 \
	divert-to lo0 port 3130
```

## Rules for the router's pf.conf (regardless of proxy system)

```
egress = em0
ingress = em1
proxy = "10.121.10.81"

# [Forward Proxy] Route all web traffic to the proxy
pass in quick on $ingress proto tcp \
	from ! $proxy to port { 80, 443 } \
	route-to $proxy

# Allow all web traffic originating from the proxy out to the outside world
pass out on $egress proto tcp \
	from $proxy to any port { 80, 443 } nat-to $egress
```
