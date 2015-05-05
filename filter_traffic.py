"""
Penn State Erie, The Behrend College
CMPSC 443 project
TOR Traffic Detection

This script works to block traffic to the server that is originating from a TOR exit node or a known proxy ip address
 First it generates a list of known proxies that it gathers from www.socks-proxy.net. This could be expanded to add additional sources
 Next it sniffs traffic to the local machine
 For each packet, it first checks to see if it is originating from a known proxy address and if so blocks that ip address
 TO DO:  Next, it queries Exonerator to determine if it is originating from TOR exit node and blocks the ip address if it is
 Iptables is used to block the desired ip addresses

Thanks to http://www.binarytides.com/python-packet-sniffer-code-linux/ as some of its basic sniffing code has been used in this script
"""

import socket, sys, pycurl, os, datetime, time
import atlas_tools as atlas
from struct import *
from StringIO import StringIO

allowlist = []
blocklist = []
checked = []
torlist = []

my_ip_address = socket.gethostbyname(socket.gethostname())

def populate_proxy_list (proxy_list):
  page = StringIO()	

  c = pycurl.Curl()
  c.setopt(c.URL, "http://www.socks-proxy.net")
  c.setopt(c.WRITEDATA, page)
  c.perform()
  c.close()

  page = page.getvalue()

  begin = page.find('<tr><td>')
  end = page.find('<',begin+8)

  while (begin != -1):
    proxy_list.append(page[begin+8:end])
    begin = page.find('<tr><td>',end+1)
    end = page.find('<',begin+8)

  return 

if __name__ == "__main__":  

  print "This script has this machine's IP as ", my_ip_address

  #create an INET, STREAMing socket
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

  my_proxy_list = []
  populate_proxy_list(my_proxy_list)

  i = 0
  # receive a packet
  while True:
    i = i + 1

    if (i % 2048 == 0): 
	populate_proxy_list(my_proxy_list)
	print "Checking for more proxy ip addresses"

    packet = s.recvfrom(65565)
         
    #packet string from tuple
    packet = packet[0]
     
    #take first 20 characters for the ip header
    ip_header = packet[0:20]
     
    #now unpack them :)
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
     
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
     
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    if s_addr in checked:
    	continue
    checked.append(s_addr)
     
    tcp_header = packet[iph_length:iph_length+20]
     
    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    if (source_port != 22 and dest_port != 22):    
      if (s_addr != my_ip_address and s_addr in my_proxy_list):
        if s_addr not in blocklist:
          print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
          print "Blocking ip address " + s_addr + " using command: iptables -A INPUT -p tcp -s "+s_addr+"/32 -d 0/0 -j DROP"
          os.system("iptables -A INPUT -p tcp -s "+s_addr+"/32 -d 0/0 -j DROP")
          blocklist.append(s_addr)
      else:
	ts = time.time()
        utc_ts = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
        if atlas.checkRelay(s_addr, utc_ts):
          if s_addr not in torlist:
            print "%s is Tor traffic" % s_addr
            print "Blocking ip address " + s_addr + " using command: iptables -A INPUT -p tcp -s "+s_addr+"/32 -d 0/0 -j DROP"
            os.system("iptables -A INPUT -p tcp -s "+s_addr+"/32 -d 0/0 -j DROP")
            torlist.append(s_addr)
        else:
          if s_addr not in allowlist:
            print "Traffic from " + s_addr + " is allowed"
            allowlist.append(s_addr)

#        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
#        print "Blocking ip address ", d_addr
##        call(["iptables", "-A INPUT -p tcp -s "+d_addr+"/32 -d 0/0 -j DROP"])
##        print "-A INPUT -p tcp -s "+d_addr+"/32 -d 0/0 -j DROP"
#        os.system("iptables -A INPUT -p tcp -s "+d_addr+"/32 -d 0/0 -j DROP")
