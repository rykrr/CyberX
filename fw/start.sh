#!/bin/bash

source /opt/fw/common.sh

clear_table nat
clear_table mangle

add_chain iptables $addr4
intercept iptables $addr4 $zero4 80  8080
intercept iptables $addr4 $zero4 443 8443
bypass iptables

add_chain ip6tables $addr6
intercept ip6tables $addr6 $zero6 80  8080
intercept ip6tables $addr6 $zero6 443 8443
bypass ip6tables

if [[ `ip rule list fwmark 1/1 | wc -l` -eq 0 ]]; then
        ip rule add fwmark 1/1 table $rt_table
        ip route add local 0.0.0.0/0 dev lo table $rt_table
fi
