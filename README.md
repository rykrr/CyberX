# CyberX Proxy Cookbook

IPv4: `10.121.10.81/24`

IPv6: `fd00:a:7900:a::51/64`


## [Apache Traffic Server v10](https://trafficserver.apache.org/) on OpenSUSE 15.3

### Getting Started
After setting up OpenSUSE, the following packages should be installed with `zypper in`:
- git
- curl

### Installing ATS
ATS does not appear to be available in the OpenSUSE repositories, but can be compiled from source by following the following instructions modified from [the docs](https://docs.trafficserver.apache.org/en/latest/getting-started/index.en.html#installing-from-source-code).

Install the following packages with `zypper in`:
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
git clone https://git-wip-us.apache.org/repos/asf/trafficserver.git
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

## Setting up networking and iptables routing
OpenSUSE uses the firewalld front-end, however, all manuals and reference guides:

Networking can be set up using the `yast` interface. The test environment has 2 interfaces `eth0`, for accessing the machine, and `eth1`, for proxying traffic. Note that IPv4 and v6 forwarding must be enabled in the `Routing` tab.

The following script, based on the example doc, will intercept packets and pass them along to the proxy port. Since packets 

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

	# Mark return traffic
	$command -t mangle -A PREROUTING -i $iface \
		-d $address -p tcp -m tcp --sport $origin_port \
		-j MARK --set-mark 1/1
}

intercept iptables  $v4 80  8080
intercept ip6tables $v6 80  8080
intercept iptables  $v4 443 4433
intercept ip6tables $v6 443 4433

ip rule add fwmark 1/1 table $rt_table
ip route add local 0.0.0.0/0 dev lo table $rt_table
```

## Forward HTTP Proxy
The following two lines enable HTTP proxying
```
CONFIG proxy.config.http.server_ports STRING 8080:tr-in:ip-out=10.121.10.81
CONFIG proxy.config.http.max_proxy_cycles INT 1
```

The port specification is as follows:
- `<port>`: This is the port ATS will listen on
- `tr-in`: Intercept packets that are not intended for the proxy
- `ip-out=address`: The address to use when reaching out to remote (origin) servers

For IPv6 configurations, the `ipv6` option must be specified and the address must be enclosed in square brackets.

The `ssl` option enables ssl termination, making it possible for clients to connect using HTTPS. `https2` is supposedly enabled by default in ATSv10, but the option can be specified.

## Enabling HTTPS
Generate a server certificate in the `/opt/ts/etc/ssl` directory using the following command:
```
openssl req -x509 -newkey rsa:4096 -keyout /opt/ts/etc/ssl/keys/proxy_key.pem -out /opt/ts/etc/ssl/certs/proxy.pem -sha256 -days 36
```

The `-nodes` (no DES) flag may be optionally specified to remove password protection for the certificate.

Add the following lines in `records.configs`
```
CONFIG proxy.config.ssl.server.cert.path STRING /opt/ts/etc/ssl/certs/
CONFIG proxy.config.ssl.server.private_key.path STRING /opt/ts/etc/ssl/keys/
```

## Enabling SSL Server Verification
The following settings in `records.config` will enforce SSL verifaction of servers.
```
CONFIG proxy.config.ssl.client.verify.server.policy STRING ENFORCED
CONFIG proxy.config.ssl.client.CA.cert.path STRING /etc/ssl/certs
CONFIG proxy.config.ssl.client.CA.cert.filename STRING ca-bundle.pem
```

#### TODO
- Test this configuration
- Adding a custom certificate to the CA bundle.

## Enabling Verbose Output
Adding the following lines will include 
```
CONFIG proxy.config.diags.output.alert STRING E
CONFIG proxy.config.diags.output.emergency STRING E
CONFIG proxy.config.diags.output.error STRING E
CONFIG proxy.config.diags.output.fatal STRING E
CONFIG proxy.config.diags.output.note STRING E
CONFIG proxy.config.diags.output.status STRING E
CONFIG proxy.config.diags.output.warning STRING E
```

The above options do not display details about requests
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

# [Forward Proxy] Route all webtraffic through the proxy
pass in quick on $ingress proto tcp \
	from ! $proxy to port { 80, 443 } \
	route-to $proxy

# [Reverse Proxy] Route all inbound traffic through the proxy (not yet tested)
pass in quick on $egress proto tcp \
	from any to ! $proxy port { 80, 443 } \
	route-to $proxy

# Allow all 
pass out on $egress proto tcp \
	from $proxy to any port { 80, 443 } nat-to $egress
pass out
```
