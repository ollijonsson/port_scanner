import sys

from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import summarize_address_range

from utils.parser import Parser
from utils.scanner import Scanner
from utils.file_io import save_csv

def main():
	# Initialize parser
	parser = Parser()

	# Get parsed arguments
	hosts = parser.hosts
	ports = parser.ports
	discovery = parser.host_discovery
	stype = parser.scan_type
	rand_ips = parser.rand_ips
	rand_ports = parser.rand_ports

	# Initialize scanner with user defined settings
	scanner = Scanner(discovery, stype, rand_ips, rand_ports)

	# Scan and get output from scan
	output = scanner.scan(hosts, ports)

	# Print output
	names = output['Host'].unique().tolist()
	for name in names:
		host_output = output.loc[output['Host'] == name]
		summary = host_output.groupby(['Host', 'Status'])
		summary = summary.agg({'Status': ['count']}).rename(columns={'Status': '', 'count': ''})
		open_ports = host_output.loc[output['Status'] == 'open']
		closed_ports = host_output.loc[output['Status'] == 'closed']
		filtered_ports = host_output.loc[output['Status'] == 'filtered']

		print(summary)
		print('\n%s\t%s\t%s' %('Port', 'Desc', 'Status'))
		for _, row in open_ports.iterrows():
			print('%d\t%s\topen' %(row['Port'], row['Description']))
		if parser.show_closed:
			for _, row in closed_ports.iterrows():
				print('%d\t%s\tclosed' %(row['Port'], row['Description']))
			for _, row in filtered_ports.iterrows():
				print('%d\t%s\tfiltered' %(row['Port'], row['Description']))
	
	# Save output file
	if parser.output:
		save_csv(output)
		


if __name__ == "__main__":
	main()
