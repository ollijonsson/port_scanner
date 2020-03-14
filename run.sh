#!/bin/bash

python3 port_scanner.py \
    --scan_type 'SYN' \
    --ip_list data/ip_list.txt \
    --port_list data/ports.txt \
    --show_closed True \
    #--cidr 192.168.100.14/24 \
    #--host scanme.nmap.org \
    #--low_port 20 \
    #--high_port 30 \
    #--host_discovery False \
    #--rand_ports True \
    #--rand_ips True \
    #--output False \