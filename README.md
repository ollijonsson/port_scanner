## Port scanner
This is a mid-term project in a Computer System Security class.

### Functionality
This tool can scan ports on networked systems with the following types of scans:
* Full TCP handshake
* SYN scan (stealth attack)
* ACK attack
* XMAS scan (a christmas tree packet with FIN, URG and PSH flags)

Hosts to scan can be provided as:
* A single hostname / ip address as a string flag
* A txt file with list of ip addresses seperated by newline
* A single address in CIDR notation as a string flag

Ports to scan can be provided as:
* A range of ports as integer flags
* A txt file with list of ports seperated by newline
* Built in list of 50 most popular ports (defined by wikipedia)

By default it performs **host discovery** before scanning provided hosts. Optionally it can **shuffle** the hosts and ports before starting the scan to better avoid detection. After scanning a summary of the results is printed along with a list of open ports. Results are also output to a csv file.


### Prerequisites
The project uses python3 and scapy which works best on linux platforms. For SYN scanning root access is needed. Example run batch script is included.

### Gettings started on debian
```
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

### Usage
```
usage: port_scanner.py [-h] [--host HOST] [--cidr CIDR] [--ip_list IP_LIST]
                       [--port_list PORT_LIST] [--low_port LOW_PORT]
                       [--high_port HIGH_PORT] [--scan_type SCAN_TYPE]
                       [--host_discovery HOST_DISCOVERY]
                       [--rand_ports RAND_PORTS] [--rand_ips RAND_IPS]
                       [--show_closed SHOW_CLOSED] [--output OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  --host str            hostname to scan
  --cidr str            cidr range to scan
  --ip_list str         path to ip list txt
  --port_list str       path to port txt
  --low_port int        low end of port range
  --high_port int       high end of port range
  --scan_type str       type of scan performed: FULL, SYN, ACK, XMAS
  --host_discovery bool host discovery toggle
  --rand_ports bool     random  order of ports
  --rand_ips bool       random order of ips
  --show_closed bool    display closed and filtered ports in output
  --output bool         save output to output.csv in root folder
  ```

### Sample run script
```
#!/bin/bash

python3 port_scanner.py \
    --scan_type 'SYN' \
    --ip_list data/ip_list.txt \
    --port_list data/ports.txt \
    --show_closed True \
```