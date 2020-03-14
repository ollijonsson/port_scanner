## Port scanner
This is a mid-term project in a Computer System Security class.

### Prerequisites
The project uses python3 and scapy which works best on linux platforms. For SYN scanning root access is needed. Example run batch script is included.

### Gettings started on debian
```
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ sudo ./run.sh
```

### Usage
```
usage: port_scanner.py [-h] [--host HOST] [--cidr CIDR] [--ip_list IP_LIST]
                       [--port_list PORT_LIST] [--low_port LOW_PORT]
                       [--high_port HIGH_PORT] [--scan_type SCAN_TYPE]
                       [--host_discovery HOST_DISCOVERY]
                       [--rand_ports RAND_PORTS] [--rand_ips RAND_IPS]
                       [--show_closed SHOW_CLOSED] [--output OUTPUT]

Port Scanner

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Hostname
  --cidr CIDR           CIDR notation
  --ip_list IP_LIST     Path to ip file
  --port_list PORT_LIST
                        Path to port file
  --low_port LOW_PORT   Low port
  --high_port HIGH_PORT
                        High port
  --scan_type SCAN_TYPE
                        Type of scan: FULL, SYN, ACK, XMAS
  --host_discovery HOST_DISCOVERY
                        Host discovery toggle
  --rand_ports RAND_PORTS
                        Random order of ports
  --rand_ips RAND_IPS   Random order of ips
  --show_closed SHOW_CLOSED
                        Display closed and filtered ports in output
  --output OUTPUT       Save output to output.csv in root folder
  ```