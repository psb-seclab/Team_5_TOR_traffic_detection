"""
	Requires:
		dpkt Python library
	Run:
		python parse_pcap.py <pcap_filename>
	Output:
		For each packet in pcap_filename:
			source: <source_string>
			destination: <destination_string>
"""

import dpkt
import socket
import sys


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

	for ts, buf in pcap:
		
		eth_layer = dpkt.ethernet.Ethernet(buf)
		ip = eth_layer.data
		tcp = ip.data

		if (type(ip) == dpkt.ip6.IP6):
			src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip.src)
			dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, ip.dst)

		elif (type(ip) == dpkt.ip.IP):
			src_ip_addr_str = socket.inet_ntop(socket.AF_INET, ip.src)
			dst_ip_addr_str = socket.inet_ntop(socket.AF_INET, ip.dst)

		#print "source:", src_ip_addr_str
		#print "destination:", dst_ip_addr_str
		#UNTESTED SO FAR
		if len(tcp.data) > 0:
			headers = dpkt.http.Request(buf).headers
			if 'via' in headers.keys() or 'forwarded-for' in headers.keys() or 'x-forwarded-for' in headers.keys():
				print "HTTP Proxy Detected: " + src_ip_addr_str


		
