#!/usr/bin/python
from scapy.all import *
from scapy.layers.inet import UDP,IP
import sys
import collections
import struct
#http://thekissinglink.blogspot.co.uk/2012/01/dhcp-discovery-using-scapy.html

def print_verbose(message):
        if verbose:
                print message

def parse_dhcp_response(resp):
        assigned_ip = None
        dhcp_server_ip = None
        is_pxe_client = False
        pxe_server = None
        pxe_file = None
        response_type = None

        assigned_ip = resp[BOOTP].yiaddr
	dhcp_server_ip = resp[BOOTP].siaddr
        pxe_server = resp[BOOTP].sname.strip('\0') # Strip null chars
        pxe_file = resp[BOOTP].file.strip('\0')

	if dhcp_server_ip is None:
		dhcp_server_ip = resp[IP].src

	if pxe_file is not None:
		is_pxe_client = True
        
        print_verbose("Source: " + resp[Ether].src)
        print_verbose("Dest: " + resp[Ether].dst) 
                
        for opt in resp[DHCP].options:
                if opt == 'end':
                        break
                elif opt == 'pad':
                        break
                elif opt[0] == 'server_id':
                        dhcp_server_ip = opt[1]
                        print_verbose("[+] Assigned IP: %s by %s" % (assigned_ip, dhcp_server_ip))
                elif opt[0] == "vendor_class_id":
                        is_pxe_client = True
                elif opt[0] == "message-type":
                        response_type = DHCPTypes[opt[1]]
		elif opt[0] == 67: # Boot File
			is_pxe_client = True
			if pxe_file is None:
				pxe_file = opt[1]
			if pxe_server is None:
				pxe_server = dhcp_server_ip

                print_verbose("DHCP Response: " + str(opt))

        print "[*] DHCP %s received from %s" % (response_type, dhcp_server_ip)
        return assigned_ip, dhcp_server_ip, is_pxe_client, pxe_server, pxe_file     

def dhcp_discover(src_mac, timeout):
        param_req_list = ("param_req_list",
                          "\x01\x02\x03\x05\x06\x0b\x0c\x0d\x0f\x10\x11\x12\x2b\x36\x3c\x43\x80\x81\x82\x83\x84\x85\x86\x87")

        disc_options = [("message-type", "discover"),
                        (param_req_list),
                        ("max_dhcp_size", 1260),
                        ("vendor_class_id", "PXEClient:Arch:00000:UNDI:002001"),
                        "end"]

        dhcp_disc = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") \
                  /IP(src="0.0.0.0", dst="255.255.255.255") \
                  /UDP(sport=68, dport=67)/BOOTP(chaddr=src_mac) \
                  /DHCP(options=disc_options)

        resp, unans = srp(dhcp_disc,retry=0,timeout=timeout,multi=1,verbose=verbose)

        results = list()

        if resp is not None:
                for r in resp:
                        results.append(parse_dhcp_response(r[1]))

                return results
        else:
                print "[-] No DHCP responses received."


def dhcp_request(src_mac,timeout,client_ip,dest_ip,dest_port):
                dhcp_req = dhcp_packet_builder("request",src_mac,client_ip,dest_ip,dest_port)
                
                resp = srp1(dhcp_req,retry=0,timeout=timeout,verbose=verbose)

                if resp is not None:
                        return parse_dhcp_response(resp)
                else:
                        print "[-] No response received."
                        exit()

def dhcp_packet_builder(message_type,src_mac,client_ip,dest_ip,dest_port):
        param_req_list = ("param_req_list",
                          "\x01\x02\x03\x05\x06\x0b\x0c\x0d\x0f\x10\x11\x12\x2b\x36\x3c\x43\x80\x81\x82\x83\x84\x85\x86\x87")

        req_options = [("message-type", message_type),
                        (param_req_list),
                        ("max_dhcp_size", 1260),
                        chr(97)+chr(17)+"\x00\x56\x4d\x6c\x50\x14\x7f\x0e\x92\x7b\x15\xc3\x32\xbd\xca\x5a\x62",
                        chr(93)+chr(2)+"\x00\x00",
                        chr(94)+chr(3)+"\x01\x02\x01",
                        ("vendor_class_id", "PXEClient:Arch:00000:UNDI:002001"),
                        "end","pad"]

        dst_mac = getmacbyip(dest_ip)
        
        return Ether(src=src_mac, dst=dst_mac) \
                        /IP(src=client_ip, dst=dest_ip) \
                        /UDP(sport=68, dport=dest_port) \
                        /BOOTP(ciaddr=client_ip,chaddr=src_mac) \
                        /DHCP(options=req_options)
        

def param_req(param_name):
        return chr(DHCPRevOptions[param_name][0])

def run():
        import argparse
        
        parser = argparse.ArgumentParser(description='Discover PXEBoot servers.')
        parser.add_argument('-m', '--method', type=int, default=1,
           help='Method to use, 1 full DHCP request (default), 2 broadcast PXE request. ')
        parser.add_argument('-t', '--timeout', type=int, default=5,
           help='Timeout value (default 5s) to listen for responses in seconds')
        parser.add_argument('-v', '--verbose', action='store_true', default=False,
           help='Provide verbose feedback')

        args = parser.parse_args()
        
        print "[*] PXEClient by Meatballs"
        
        timeout = args.timeout

        if timeout > 5:
                print "[*] Timeout value set to %s seconds" % timeout
        
        # Initialize Global Variables
        global verbose
        global bcast_mac
        global bcast_ip
        verbose = args.verbose
        bcast_mac = "ff:ff:ff:ff:ff:ff"
        bcast_ip = "255.255.255.255"

        # Scapy Configuration - Bind non default layer to receive response (WDS listens on UDP 4011)
        bind_layers( UDP,           BOOTP,         dport=68, sport=4011)
        conf.checkIPaddr = False # Process packets sent to 255.255.255.255 etc

        fam,hw = get_if_raw_hwaddr(conf.iface) # Get HW Address
        src_mac = hw #RandMAC() # Replace this

        if args.method == 1:
                print "[*] Performing full DHCP sequence"
                full_dhcp_method(src_mac, timeout)
        elif args.method == 2:
                print "[*] Performing PXE Broadcast"
                broadcast_method(src_mac, timeout)

def broadcast_method(src_mac, timeout):
        print "[*] Sending PXE DHCP Request Probe"
        
        assigned_ip, dhcp_server_ip, is_pxe_client, pxe_server, pxe_file = dhcp_request(src_mac, timeout, "0.0.0.0", bcast_ip, 4011)

        if is_pxe_client:
                print "[+] PXEClient response received from: %s" % dhcp_server_ip
                print "[+] PXE server %s" % pxe_server
                print "[+] PXE file %s" % pxe_file

        try:
                pass
                #print TFTP_read(pxe_file, pxe_server).run()
        except socket.gaierror, e:
                print "Exception, probably unable to resolve host."
                print e
        
def full_dhcp_method(src_mac, timeout):
        pxe_dhcp_server_ip = None
	pxe_file = None
        std_dhcp_server_ip = None
        client_assigned_ip = None
     
        print "[*] Sending DHCP Discovery Probe"

        discover_results = dhcp_discover(src_mac, timeout)

        for result in discover_results:
                assigned_ip, dhcp_server_ip, is_pxe_client, pxe_server, pxe_file = result
                if is_pxe_client:
                        print "[+] PXEClient response received from: %s" % dhcp_server_ip
                        print "[+] PXE server %s" % pxe_server
			print "[+] PXE file %s" % pxe_file
			pxe_dhcp_server_ip = dhcp_server_ip
                elif assigned_ip != "0.0.0.0":
                        client_assigned_ip = assigned_ip
	
        if pxe_dhcp_server_ip is not None and pxe_file is None:                     
                print "[*] Sending DHCP Request to %s on UDP port 4011" % pxe_dhcp_server_ip
                assigned_ip, dhcp_server_ip, is_pxe_client, pxe_server, pxe_file \
                        = dhcp_request(src_mac, timeout, client_assigned_ip, pxe_dhcp_server_ip, 4011)
                

if __name__ == "__main__":
        run()
