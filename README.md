# CyberX 2022 Web Proxy Cookbook (With PostEx Notes)

Author: Ryan Kerr (ryan.kerr@queensu.ca)

Date: 2022-04-14

## Table of Contents


## What is the purpose of a web proxy in CyberX?

There are two main reasons for the use of a web proxy: monitoring encrypted web traffic and filtering the contents of traffic. Most websites and browsers today use HTTPS as their default (if not only) protocol for communication. While this is great for securing communications and protecting information such as credentials, it also provides red team with the ability to establish covert channels with no way to inspect the contents. To provide blue with information about these connections, the proxy is used to man-in-the-middle HTTPS connections by presenting spoofed certificates to the client and forwarding traffic to the origin server. More details about this mechanism can be found in <todo: label>. With the web traffic being routed through and decrypted by the proxy, it becomes possible to filter and modify content at the application level and obscure the client address at the routing layer.

### Reverse Proxies

This cookbook only covers the use of *forward* proxies. A forward proxy forwards traffic from clients out to the internet, wheras reverse proxies direct traffic from the internet to one or more servers. Reverse proxies are used to map URLs to endpoint servers on the network. These mappings may be one-to-many in the case of load-balancing multiple redundant servers. Reverse proxies may also be used for SSL termination where all traffic between a client and proxy are encrypted, but traffic between the proxy and server (that may otherwise not have any encryption support) remains unencrypted.

## Why Apache Traffic Server?

Apache Traffic Server (ATS) was selected as the proxy of choice for CyberX 2022 for its support for HTTP/2.0, the QUIC protocol, transparent proxy support, and certificate spoofing plugin. The biggest downside to ATS was that it was not tested for use with OpenBSD and was not readily available on OpenSUSE repositories, requiring it be compiled from scratch.

Squid and mitmproxy were used in previous years, however, it was found that Squid has fallen behind in terms of protocol support and mitmproxy was far too unstable to use in production as-is. OpenBSD's included relayd appeared to have forward proxy capabilities, however, it did not appear to have the ability to spoof certificates or handle HTTP/2.0.

## [Apache Traffic Server](https://trafficserver.apache.org/) 9.2 on OpenSUSE 15.3

This guide was written while ATS 9.2 was still in active development and may be out of date. Please refer to the official build guide and [README](https://github.com/apache/trafficserver/blob/master/README) if something goes awry.

### Why version 9.2?

We will be using ATS as a transparent proxy. It appears that this feature was available in prior versions of ATS, but the cycle detection mechanism used to prevent a proxy from talking to itself did not account for transparent mode. This resulted in almost half of the webpages showing "Cycle Detected" errors rather than the webpage. Version 9.2.x introduced a configuration option, `proxy.config.http.max_proxy_cycles`, to manually disable cycle detection.

### Installing ATS
ATS can be compiled from source by following the following instructions modified from [the docs](https://docs.trafficserver.apache.org/en/latest/getting-started/index.en.html#installing-from-source-code). It is recommended to perform these steps as a non-root user.

Install the following packages with `sudo zypper in`:
- git
- curl
- libopenssl-devel
- zlib-devel
- pcre-devel
- libcap-devel
- make
- flex
- hwloc (this is the package missing from OpenBSD)
- lua
- gcc
- gcc-c++ (compiling with clang introduces failures in testing)
- libtool
- pkgconfig


For convenience:

```
sudo zypper in git curl libopenss-devel zlib-devel pcre-devel libcap-devel make flex hwloc lua gcc gcc-c++ libtool pkgconfig
```

Clone the ATS repository and move into the directory.

```
git clone https://github.com/apache/trafficserver
cd trafficserver
```

Select version `9.2.x`:

```
git fetch
git switch 9.2.x
```

The following steps will compile and install ATS in `/opt/ts`:

```
autoreconf -if
./configure --prefix=/opt/ts --enable-tproxy --enable-posix-cap --enable-experimental-plugins
make
make test
sudo make install
```

The installation can be verified with the following line.

```
sudo /opt/ts/bin/traffic_server -R 1
```

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

OpenSUSE uses the firewalld frontend, however, all manuals and reference guides use iptables directly. Additionally, The default firewalld configuration appears to block icmp forwarding, resulting in an ICMP host unreachable error. To avoid any issues, the rest of this cookbook assumes that firewalld is disabled.

```
systemd disable --now firewalld
```

Networking can be set up using `sudo yast`. Note that IPv4 and v6 forwarding must be enabled in the `Routing` tab.

To simplify the configuration of firewall rules, a set of scripts has been provided along with this cookbook for setting up the rules. This cookbook will briefly explain each of the functions found in the scripts.

The `common.sh` script defines the following variables:

```
# Address information
iface='vlan10'
addr4='10.121.10.81'
addr6='fd00:a:7900:a::51'

zero4='0.0.0.0'
zero6='::'

# /etc/iproute2/rt_tables: Arbitrary table number
rt_table=64
```

The `$rt_table` variable is used to identify the local routing table for ATS. This number can be any number between 0 and 255, but must be unique. You may optionally declare ``ats=64`` in the `/etc/iproute2/rt_tables` and then set `rt_table=ats` above.

In order to simplify firewall rules and quickly bypass multiple rules, the script organizes its rules into a new `PROXY` chain in the `mangle` table, and a `BYPASS` chain in the `nat` table. A packet may only enter the `PROXY` chain if it is a packet that is being forwarded by the proxy (ie. neither the source nor destination are the proxy itself). The `BYPASS` chain is used to NAT connections in the event the proxy is disabled. This chain is not activated by default, but may be activated by adding a jump rule in the `nat.POSTROUTING` chain (see `bypass` and `clear_bypass` in the included script).

```
add_chain() {
        local command=$1
        local address=$2
        $command -t mangle -N PROXY
        $command -t mangle -A PROXY -j RETURN
        $command -t mangle -A PREROUTING -i $iface ! -s $address ! -d $address -j PROXY

        $command -t nat -N BYPASS
        $command -t nat -A BYPASS -j RETURN
}
```

Now that chains have been established, they can be populated with rules for the individual ports. This command adds a rule to transparently forward packets to the local proxy software using the local routing table. When picked up by these TPROXY rules, only the port numbers are modified. In addition to these rules, a rule for the corresponding port is added to the `BYPASS` chain. When active, these rules will rewrite the packets 

```
intercept() {
        local command=$1
        local address=$2
        local zero_address=$3
	local protocol=$4
        local origin_port=$5
        local proxy_port=$6

        # Pass intercepted traffic to the local proxy port
        $command -t mangle -I PROXY -p $protocol --dport $origin_port \
                -j TPROXY --on-ip $zero_address --on-port $proxy_port --tproxy-mark 1/1

        $command -t nat -I BYPASS -p $protocol --dport $origin_port -j SNAT --to $address
}
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


## Starting ATS

ATS can be manually started using `sudo /opt/ts/bin/traffic_server`. The provided management script, `/opt/ts/bin/trafficserver`, is based on an older version of OpenSuse, so it is recommended to use the server binary directly.

Since we will be running ATS is a production-like environment and it would be beneficial to start ATS on boot in the event the server restarts, the following systemd unit file can be used to manage ATS with sytsemctl. Write the following unit file (`ats.service`) to `/etc/systemd/system`:

```
[Unit]
Description=Apache Traffic Server
After=network-pre.target

[Service]
Type=simple
PIDFile=/opt/ts/var/trafficserver/server.lock
ExecStartPre=/opt/fw/start.sh
ExecStartPre=/opt/fw/bypass.sh
ExecStart=/opt/ts/bin/traffic_server
ExecStartPost=/opt/fw/clear_bypass.sh
ExecStopPost=/opt/fw/bypass.sh

[Install]
WantedBy=multi-user.target
```

Run `systemctl enable ats` to have ATS initialize on boot.

When started with systemd (at boot or explicitly with `systemctl start ats`), this unit file will set the necessary firewall rules for proxying. In the event of an error, systemd will trigger the bypass script, allowing web traffic to continue flowing without going through the potentially failed proxy.


## Routing traffic to the proxy

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
