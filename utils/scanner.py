import sys

from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import sr, sr1
from scapy.volatile import RandShort
from scapy.sendrecv import send
from random import shuffle

import pandas as pd
import enlighten

class Scanner():

    def __init__(self, discovery, stype, rand_ports, rand_ips):
        self.manager = enlighten.get_manager()
        self.SYNACK = 0x12
        self.RSTACK = 0x14
        self.RST = 0x04
        self.timeout = 0.3

        # User defined settings
        self.host_discovery = discovery
        self.stype = stype
        self.rand_ports = rand_ports
        self.rand_ips = rand_ips

    def discover_hosts(self, hosts):
        """ Host discovery of a list of hosts. """
        active_hosts = []
        for target in hosts:
            ans, _ = sr(IP(dst=target) / ICMP(), verbose=False, timeout=5)
            for host in ans:
                _, b = host
                active_hosts.append(b.src) # Append active host
        return active_hosts

    def check_host(self, host):
        """ Check if host is online """
        try:
            ip = IP(dst=host)
            icmp = ICMP()
            sr1(ip / icmp, verbose=False, timeout=1)
            return True
        except Exception:
            return False
    
    def syn_scan(self, ip, sport, dport, full_scan):
        """ Perform a full tcp handshake scan or a SYN scan """
        SYN = TCP(sport=sport, dport=dport, flags='S')

        # Send SYN and recieve SYNACK or RSTACK
        SYNACK = sr1(ip / SYN, timeout=self.timeout, verbose=False)

        if SYNACK:
            if SYNACK.haslayer(TCP):

                flags = SYNACK.getlayer(TCP).flags
                # If response is RST, port is closed
                if flags == self.RST or flags == self.RSTACK:
                    return 'closed'

                # Else if response is SYN + ACK, port is open
                elif flags == self.SYNACK:

                    # If SYN scan, send RST back
                    if not full_scan:
                        RST = TCP(sport=sport, dport=dport, flags='R')
                        send(RST, verbose=False)
                    # If FULL scan, send ACK back
                    else:
                        ACK = TCP(
                            sport=sport,
                            dport=dport,
                            flags='A',
                            ack=SYNACK.seq + 1
                        )
                        send(ip/ACK, verbose=False)

                    return 'open'

                # Port is closed, send RST
                else:
                    return 'closed'
        else:
            return 'closed'

    
    def ack_scan(self, ip, sport, dport):
        """ Perform an ACK scan """
        ACK = TCP(dport=dport, flags='A')
        ACK_SCAN = sr1(ip/ACK, timeout=self.timeout, verbose=False)

        if not ACK_SCAN:
            return None
        else:
            if ACK_SCAN.haslayer(TCP):
                flags = ACK_SCAN.getlayer(TCP).flags

                # If response is RST, port is unfiltered
                if flags == self.RST or flags == self.RSTACK:
                    return 'unfiltered'
            elif ACK_SCAN.haslayer(ICMP):
                ICMP_type = ACK_SCAN.getlayer(ICMP).type
                ICMP_code = ACK_SCAN.getlayer(ICMP).code

                # If response is ICMP error, port is filtered
                if ICMP_type == 3 and int(ICMP_code) in [1,2,3,9,10,13]:
                    return 'filtered'
                else:
                    return None
            else:
                return None
    
    def xmas_scan(self, ip, sport, dport):
        """ Perform a XMAS scan """
        XMAS = TCP(sport=sport, dport=dport, flags='FPU')
        XMAS_SCAN = sr1(ip/XMAS, timeout=self.timeout, verbose=False)

        # If no response, port is open | filtered
        if not XMAS_SCAN:
            return 'open | filtered'
        else:
            if XMAS_SCAN.haslayer(TCP):
                flags = XMAS_SCAN.getlayer(TCP).flags

                # If response is RST, port is closed
                if flags == self.RST or flags == self.RSTACK:
                    return 'closed'
            elif XMAS_SCAN.haslayer(ICMP):
                ICMP_type = XMAS_SCAN.getlayer(ICMP).type
                ICMP_code = XMAS_SCAN.getlayer(ICMP).code

                # If response is ICMP error, port is filtered
                if ICMP_type == 3 and int(ICMP_code) in [1,2,3,9,10,13]:
                    return 'filtered'
                else:
                    return None
            else:
                return None

    def scan_port(self, target, port):
        """ Scan a single port with selected type of scanning """
        sport = RandShort() # Source port
        ip = IP(dst=target) # IP
        
        # Select scan method based on user settings
        if self.stype == 'FULL':
            return self.syn_scan(
                ip=ip,
                sport=sport,
                dport=port,
                full_scan=True)

        elif self.stype == 'SYN':
            return self.syn_scan(
                ip=ip,
                sport=sport,
                dport=port,
                full_scan=False)

        elif self.stype == 'ACK':
            return self.ack_scan(
                ip=ip,
                sport=sport,
                dport=port)

        else:
            return self.xmas_scan(
                ip=ip,
                sport=sport,
                dport=port)

    def scan(self, hosts, ports):
        """ Scans all provided hosts with the selected options. """
        if self.host_discovery:
            hosts = self.discover_hosts(hosts)
        if self.rand_ips:
            shuffle(hosts)
        if self.rand_ports:
            ports = ports.sample(frac=1)

        # Display total progress bar if multiple hosts
        if len(hosts) > 1:
            total_pbar = self.manager.counter(total=len(hosts) * len(ports), desc='Total')
        
        # New empty output dataframe
        output = pd.DataFrame(columns=['Host', 'Port', 'Description', 'Status'])

        # Scan hosts
        for host in hosts:
            ports_pbar = self.manager.counter(total=len(ports), desc=host)
            dropped = is_open = closed = filtered = unfiltered = open_filtered = 0
            for _, row in ports.iterrows():
                # Read response
                response = self.scan_port(host, row['port'])
                if response == None:
                    response = 'connection dropped'
                    dropped += 1
                elif response == 'open':
                    is_open += 1
                elif response == 'closed':
                    closed += 1
                elif response == 'filtered':
                    filtered += 1
                elif response == 'unfiltered':
                    unfiltered += 1
                elif response == 'open | filtered':
                    open_filtered += 1

                # Append result to dataframe
                output = output.append({
                    'Host': host,
                    'Port': row['port'],
                    'Description': row['description'],
                    'Status': response
                }, ignore_index=True)

                ports_pbar.update()

                # If multiple hosts
                if len(hosts) > 1:
                    total_pbar.update()
        
        self.manager.stop()
        return output