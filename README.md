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

### Setting up a dedicated trafficserver user

ATS requires read access to the CA certificate and keys, however, ATS uses the `nobody` account by default. To provide access to ATS specifically, it is probably a good idea to create a new user.

```
useradd -UMrs /sbin/nologin ts
```

To tell ATS to use this new user, it must be specified in `records.config`:

```
CONFIG proxy.config.admin.user_id STRING ts
```

### Setting up networking and iptables routing

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

The `$rt_table` variable is used to identify the local routing table for ATS. This number can be any number between 0 and 255, but must be unique. You may optionally declare ``ats=64`` in the `/etc/iproute2/rt_tables` and then set `rt_table=ats` above. The following rules initialize a local table to capture local proxy traffic:

```
if [[ `ip rule list fwmark 1/1 | wc -l` -eq 0 ]]; then
        ip rule add fwmark 1/1 table $rt_table
        ip route add local 0.0.0.0/0 dev lo table $rt_table
fi
```

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

Now that chains have been established, they can be populated with rules for the individual ports. This command adds a rule to transparently forward packets to the local proxy software using the local routing table. When picked up by these TPROXY rules, only the port numbers are modified. In addition to these rules, a rule for the corresponding port is added to the `BYPASS` chain. When active, these rules will source-NAT the packets (ie. rewrite the packet's source address and forward the response to the sender) instead of using the proxy software.

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

These functions are used in `/opt/fw/start.sh` to initialize the firewall tables:

```
source /opt/fw/common.sh

clear_table nat
clear_table mangle

add_chain iptables $addr4
intercept iptables $addr4 $zero4 tcp 80  8080
intercept iptables $addr4 $zero4 tcp 443 8443
intercept iptables $addr4 $zero4 udp 443 8553
bypass iptables

add_chain ip6tables $addr6
intercept ip6tables $addr6 $zero6 tcp 80  8086
intercept ip6tables $addr6 $zero6 tcp 443 8446
intercept ip6tables $addr6 $zero6 udp 443 8556
bypass ip6tables
```

### Basic ATS Configuration
Setting up a basic HTTP interception proxy is possible by using the `tr-in` option in the server port specification within `records.config`. Since the OpenBSD router is set to only route web traffic from the proxy to external networks, the `ip-out` option acts as a NAT by not spoofing the requesting address.

```
CONFIG proxy.config.http.server_ports STRING 8080:tr-in:ip-out=10.121.10.81 8086:ipv6:tr-in:ip-out=[fd00:a:7900:a::51] 8443:ssl:tr-in:ip-out=10.121.10.81 8446:ssl:ipv6:tr-in:ip-out=[fd00:a:7900:a::51] 8553:quic:tr-in:ip-out=10.121.10.81 8556:ipv6:quic:tr-in:ip-out=[fd00:a:7900:a::51]

CONFIG proxy.config.http.max_proxy_cycles INT 1
CONFIG proxy.config.url_remap.remap_required INT 0
```

(Note: there are options that supposedly make specifying the address in `ip-out` redundant, but it didn't work as expected during testing)

For `quic`, a certificate authority *must* be specified in `/opt/ts/etc/trafficserver/ssl_multicert.config`.

The second configuration line is a new feature added to ATS 9.2 to prevent the cycle detection mechanism from blocking connections that would end up back at the proxy. Since the firewall rules and routing rules on the network are set up in such a way that a cycle should be impossible, this check is unecessary (and is oftentimes wrong when in transparent mode). Disabling it ensures clients won't see a "Proxy Cycle Detected" error message.

The third line is for URL re-mapping used for reverse proxying and is set as required by default. Since ATS is only being used as a forward proxy, this should be disabled.


### HTTPS and Certificate Authorities
In order for the proxy to intercept HTTPS requests, the server must be able to generate fake certificates for each of the websites requested by the clients. To achieve this, ATS requires a signing certificate or Certificate Authority (CA). Since this certificate will only be used within RMCG BlueNet, this certificate can either be self-signed with the certificate distributed to all RMCG BlueNet hosts or be signed by the RMCG BlueNet certificate authority. In the former case, it is important to communicate this requirement to netops to ensure the certificate is installed on every machine. The latter case may not be possible if the upstream certificate has restrictions on the names that can be signed or the number of intermediate certificate authorities (pathlen). White cell has indicated that they will not make any exceptions to restrictions imposed on certificates.

To generate a self-signed certificate for standalone distribution using EasyRSA:

```
EASYRSA=. ./easyrsa init-pki
EASYRSA=. ./easyrsa build-ca
```

If this certificate is to be signed by the upstream certificate authority, pass `subca` as an argument to `build-ca`

This certificate must be readable by the user running trafficserver and all files must not contain any text prior to the `--BEGIN *--` lines. Failure to do so will result in ATS crashing with a SEGFAULT.

The `nopass` option may be passed to `build-ca` to remove password protection for the certificate key. Using a key is recommended, but this necessitates the password being accessible somewhere on the system or entered manually at runtime. Version 9.2 with OpenSSL ignored the `ssl_key_diag` option in `ssl_multicert.config`, meaning a separate `expect` script had to be used to input the key passed by the admin user to root using `keyctl` (this script is included with this cookbook, but finding a way to make `ssl_key_diag` is recommended if at all possible)

ATS uses the certifier plugin to spoof certificate names. This plugin can be enabled by adding the following line to `plugins.config`.

```
certifier.so --sign-cert /opt/ts/etc/ssl/ca.crt --sign-key /opt/ts/etc/ssl/private/ca.key --sign-serial /opt/ts/etc/ssl/ca.srl --store /opt/ts/etc/ssl/certs --max 10000
```

It should be noted that the `store` and `max` parameters are required. Omitting these options will result in a segmentation fault with no helpful error message. Setting this number high is recommended if there is enough space so that the generated certificates can be archived so that packet captures can be analyzed in the future.

The following options can be added to `records.config` to enforce verification of remote HTTPS servers:

```
CONFIG proxy.config.ssl.client.verify.server.policy STRING ENFORCED
CONFIG proxy.config.ssl.client.CA.cert.path STRING /etc/ssl/certs
CONFIG proxy.config.ssl.CA.cert.path STRING /etc/ssl/certs
```

### Removing Headers
By default, ATS adds forward and server headers that expose the requesting client and server version. The following options can be set to prevent these headers from being included.

```
CONFIG proxy.config.http.insert_client_ip INT 0
CONFIG proxy.config.http.insert_squid_x_forwarded_for INT 0
CONFIG proxy.config.http.response_server_enable INT 0
CONFIG proxy.config.http.insert_request_via_str INT 0
CONFIG proxy.config.http.insert_response_via_str INT 0
CONFIG proxy.config.http.insert_age_in_response INT 0
```

### Hiding User Agents
This option could be potentially useful, but may break compatibility with some websites.

```
CONFIG proxy.config.http.global_user_agent_header STRING ""
```

### Logging and Filtering Data

This is one area that wasn't covered to the extent that I had hoped this year. ATS has a number of facilities for logging data, including dumping all traffic to JSON or streaming data using ICAP. The exact method to use will depend on the amount of disk space available to the proxy, the types of logs needed, and the needs of the IDS lead and SOC team. In the future, the proxy lead should communicate with the IDS lead as early as possible to establish what to log and how to deliver the logs. If ICAP is used, a separate server will be required to read and filter this traffic without introducing large amounts of latency.

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

## Monitoring ATS
A status script has been included to monitor the state of the traffic proxy. This script only monitors the state through systemd and iptables. Since it uses sudo to execute these commands, it requires sudo to be password-less in the sudoers file and is rather noisy in journalctl logs. I'd recommend replacing it with something that uses ATS's built-in monitoring commands or even integrating it with a dashboard, such as graphana.  

![Status Panel](ats_status.png)

## Routing traffic to the proxy (for firewall lead)

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
