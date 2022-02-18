#!/bin/bash

# Address information
iface='eth1'
addr4='10.121.10.81'
addr6='fd00:a:7900:a::51'

# /etc/iproute2/rt_tables: Arbitrary table number
rt_table=64

rst() {
        iptables -t $1 -F
        iptables -t $1 -X
}

add_chain() {
        local command=$1
        local address=$2
        $command -t mangle -N PROXY
        $command -t mangle -A PROXY -j RETURN
        $command -t mangle -A PREROUTING -i $iface ! -s $address ! -d $address -j PROXY

        $command -t nat -N BYPASS
        $command -t nat -A BYPASS -j RETURN
}

intercept() {
        local command=$1
        local address=$2
        local origin_port=$3
        local proxy_port=$4

        # Pass intercepted traffic to the local proxy port
        $command -t mangle -I PROXY -p tcp --dport $origin_port \
                -j TPROXY --on-ip 0.0.0.0 --on-port $proxy_port --tproxy-mark 1/1

        $command -t nat -I BYPASS -p tcp --dport $origin_port -j SNAT --to $address
}

enable_bypass() {
        local command=$1
        if ! $command -t nat -C POSTROUTING -j BYPASS 2>/dev/null; then
                $command -t mangle -I PREROUTING -j ACCEPT
                $command -t nat -I POSTROUTING -j BYPASS
        fi
}

disable_bypass() {
        local command=$1
        $command -t mangle -D PREROUTING -j ACCEPT 2>/dev/null
        $command -t nat -D POSTROUTING -j BYPASS 2>/dev/null
}
