import sys
import argparse
import pandas as pd
import numpy as np
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import summarize_address_range

from utils.file_io import get_top_50_ports, get_all_ports, read_file

class Parser:
    def __init__(self):
        parser = self.get_parser()
        args = parser.parse_args()
        self.hosts = self.get_hosts(args)
        self.ports = self.get_ports(args)
        self.scan_type = args.scan_type
        self.host_discovery = args.host_discovery
        self.rand_ips = args.rand_ips
        self.rand_ports = args.rand_ports
        self.show_closed = args.show_closed
        self.output = args.output

    def get_parser(self):
        parser = argparse.ArgumentParser(
            description='Port Scanner',
            add_help=True)
        parser.add_argument('--host', help="Hostname")
        parser.add_argument('--cidr', type=str, help="CIDR notation")
        parser.add_argument('--ip_list', type=str, help="Path to ip file")
        parser.add_argument('--port_list', type=str, help="Path to port file")
        parser.add_argument('--low_port', type=int, help="Low port")
        parser.add_argument('--high_port', type=int, help="High port")
        parser.add_argument('--scan_type', type=str, default='FULL', help='Type of scan: FULL, SYN, ACK, XMAS')
        parser.add_argument('--host_discovery', type=bool, default=True, help='Host discovery toggle')
        parser.add_argument('--rand_ports', type=bool, default=False, help='Random order of ports')
        parser.add_argument('--rand_ips', type=bool, default=False, help='Random order of ips')
        parser.add_argument('--show_closed', type=bool, default=False, help='Display closed and filtered ports in output')
        parser.add_argument('--output', type=bool, default=True, help='Save output to output.csv in root folder')
        return parser
    
    def get_hosts(self, args):
        hosts = []

        # Append all provided hosts to list
        if args.host is not None:
            hosts.append(args.host)

        if args.cidr is not None:
            nw = ip_network(args.cidr)
            for ip in nw:
                hosts.append(str(ip))

        if args.ip_list is not None:
            data = read_file(args.ip_list)
            for _, row in data.iterrows():
                hosts.append(row['data'])
        
        # If no hosts are provided, use demo
        if len(hosts) == 0:
            hosts.append('scanme.nmap.org')
        
        return hosts
        
    def get_ports(self, args):
        ports = []
        # Determine list of ports to use
        if args.port_list is None:
            if args.low_port is not None or args.high_port is not None:
                # Try using port low to high port range
                low = args.low_port
                high = args.high_port
                try:
                    if low > 0 and low < high:
                        ports = [i for i in range(low, high + 1)]
                except:
                    print('Specified port range invalid')
            else:
                # Use top 50 ports
                ports = get_top_50_ports()
        else:
            # Use user defined ports
            all_ports = get_all_ports()
            user_ports = read_file(args.port_list)

            # Create dataframe and append description of ports if available
            descriptions = [None for i in range(len(user_ports))]
            user_ports = [row['data'] for _, row in user_ports.iterrows()]
            ports = pd.DataFrame(
                np.column_stack([user_ports, descriptions]),
                columns=['port', 'description']
            )
            for _, row in ports.iterrows():
                new = all_ports.loc[all_ports['port'] == row['port']]
                if not new.empty:
                    row['description'] = new.iloc[0]['description']
                else:
                    row['description'] = 'none'
        
        # Return list of ports
        return ports