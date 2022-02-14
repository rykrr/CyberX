# CyberX Proxy Cookbook

IPv4: `10.121.10.81/24`

IPv6: `fd00:a:7900:a::51/64`

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

### Rules that need to be added to the firewall's pf.conf
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
```
