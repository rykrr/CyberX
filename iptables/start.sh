#!/bin/bash

source /opt/iptables/firewall.sh

clear_table nat
clear_table mangle

add_chain iptables $addr4
intercept iptables $zero4 $addr4 80  8080
intercept iptables $zero4 $addr4 443 8443

add_chain ip6tables $addr6
intercept ip6tables $zero6 $addr6 80  8080
intercept ip6tables $zero6 $addr6 443 8443

if [[ `ip rule list fwmark 1/1 | wc -l` -eq 0 ]]; then
        ip rule add fwmark 1/1 table $rt_table
        ip route add local 0.0.0.0/0 dev lo table $rt_table
fi
