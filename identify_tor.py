"""
	Requires:
		dpkt Python library
		Requests Python library (indirectly required via atlas_tools.py)
	Run:
		python identify_tor.py <pcap_filename>
	Output:
		For each destination IP in pcap_filename:
			If IP is Tor relay: 	<IP> is Tor traffic
			If IP is not Tor relay	<IP> is not Tor traffic 
"""

import dpkt
import socket
import sys
import atlas_tools as atlas
import datetime


if __name__ == "__main__":

	if len(sys.argv) != 2:
		print "Usage: parse_pcap.py filename"
		sys.exit(-1)


	try:
		inFile = open(sys.argv[1])
	except:
		print "Error opening file %s" % sys.argv[1]
		exit(-2)

	pcap = dpkt.pcap.Reader(inFile)
	destinations = []

	for ts, buf in pcap:
		
		eth_layer = dpkt.ethernet.Ethernet(buf)
		ip = eth_layer.data
		
		if (type(ip) == dpkt.ip6.IP6):
			src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip.src)
			dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip.dst)

		elif (type(ip) == dpkt.ip.IP):
			src_ip_addr_str = socket.inet_ntop(socket.AF_INET, ip.src)
			dst_ip_addr_str = socket.inet_ntop(socket.AF_INET, ip.dst)

		if destinations.count(dst_ip_addr_str) < 1:
			destinations.append(dst_ip_addr_str)


	for destination in destinations:

		utc_ts = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d')

		if atlas.checkRelay(destination, utc_ts):
			print "%s is Tor traffic" % destination
		else:
			print "%s is not Tor traffic" % destination
