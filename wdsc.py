## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## This program is published under a GPLv2 license

#http://msdn.microsoft.com/en-us/library/dd541332(prot.20).aspx

import socket,struct

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP
from scapy.ansmachine import *


guid = "\x5a\xeb\xde\xd8\xfd\xef\xb2\x43\x99\xfc\x1a\x8a\x59\x21\xc2\x27"

#http://msdn.microsoft.com/en-us/library/dd891406(prot.20).aspx
opcodes = {	0x00000002:"IMG_ENUMERATE",
		0x00000003:"LOG_INIT",
		0x00000004:"LOG_MSG",
		0x00000005:"GET_CLIENT_UNATTEND",
		0x00000006:"GET_UNATTEND_VARIABLES",
		0x00000007:"GET_DOMAIN_JOIN_INFORMATION",
		0x00000008:"RESET_BOOT_PROGRAM",
		0x000000C8:"GET_MACHINE_DRIVER_PACKAGES",}
		# 0x00000002:"OP_QUERY_METADATA" } # This clashes with first opcode?

class NameField(StrFixedLenField):
	def i2repr(self, pkt, x):
		return x.replace('\x00',' ')
		

class WDSC_Variable_Description_Block(Packet):
        name = "Microsoft Windows Deployment Services Control Protocol - Variable Description Block"
        fields_desc = [ NameField("Name", None, 66),#Must end in null char
			LEShortField("Padding1", 0x00),
			LEShortEnumField("Base_Type", None, {0x0001:"BYTE",0x0002:"USHORT",0x0004:"ULONG",0x008:"ULONG64",0x0010:"STRING", 0x0020:"WSTRING",0x0040:"BLOB"}),
			LEShortEnumField("Type_Modifier", 0x0000, {0x0000:"None",0x1000:"ARRAY"}),
			#FieldLenField("Value_Length", None, "Value", "!I"),
			LEIntField("Value_Length", None),
			LEIntField("Array_Size", None)]
			#StrField("Value", None)]
			#StrLenField("Value", "", "Value_Length")]
			#Data and Padding pulled out as Raw values for now. 
			#We should also know the number of variables from the operation header...
	def extract_padding(self, pkt):
		if self.Value_Length is not None:
			length = self.Value_Length 
			padding = 16-(length % 16) # The amount of padding that should be after the value (rounds value to 16 bytes)
			length = length + padding
			return pkt[:length], pkt[length:]
		else:
			return "",pkt

class WDSC_Variable_Section(Packet):
        name = "Microsoft Windows Deployment Services Control Protocol - Variable Section"
        fields_desc = [ PacketListField("Description_Blocks", [], WDSC_Variable_Description_Block)]
	
        def extract_padding(self, pkt):
                return "",pkt


class WDSC_Operation_Header(Packet):
        name = "Microsoft Windows Deployment Services Control Protocol - Operation Header"
        fields_desc = [ LEIntField("Packet_Size", None), # Must be sum of bytes of Op Header and Variables
                        LEShortField("Version", 0x0100),
                        ByteEnumField("Packet_Type", None, {0x01:"REQUEST",0x02:"REPLY"}), #0x01 WDSCPL_PACKET_REQUEST, 0x02 WDSCPL_PACKET_REPLY
                        ByteField("Padding1", 0x00), 
                        LEIntEnumField("OpCode-ErrorCode", None, opcodes),
                        LEIntField("Variable_Count", None) ] # Must be number of variables in Variables section

        def post_build(self, p, pay):
                # Calculate Packet_Size
                if self.Packet_Size is None:
                        l = len(pay) + len(p) 
                        p = struct.pack('i',l) + p[4:]

		# Calculate Variable_Count
		if self.Variable_Count is None:
			v_sec = WDSC_Variable_Section(pay)
			c = len(v_sec.Description_Blocks)
			p = p[:12] + struct.pack('i', c) 			

		return p+pay

        def extract_padding(self, pkt):
                return "",pkt


class WDSC_Endpoint_Header(Packet):
        name = "Microsoft Windows Deployment Services Control Protocol - Endpoint Header"
        fields_desc = [ LEShortField("Size_Of_Header", 0x0028),
                        LEShortField("Version", 0x0100),
			LEIntField("Packet_Size", None), # Is there a clever way to do this with PacketLenField?
                        StrFixedLenField("Endpoint_GUID", guid, 16),
                        StrFixedLenField("Reserved", None, 16)]

	def post_build(self, p, pay):
		# Calculate Packet_Size
		if self.Packet_Size is None:
			l = len(pay) + len(p) # Header_Size should always be 40 (0x0028)  - Examples seem to not include the Endpoint Header against the Spec... 
			p = p[:4] + struct.pack('h',l) + p[6:]
		return p+pay

	# Not 100% what is going on here, we are fiddling with the padding which helps the dissector 
	# identify the next PacketField correctly?
	def extract_padding(self, pkt):
        	return "",pkt



class WDSC(Packet):
        name = "Microsoft Windows Deployment Services Control Packet"
        fields_desc = [ PacketField("Endpoint_Header", WDSC_Endpoint_Header(), WDSC_Endpoint_Header),
			PacketField("Operation_Header", WDSC_Operation_Header(), WDSC_Operation_Header),
			PacketField("Variables_Section", WDSC_Variable_Section(), WDSC_Variable_Section) ]

	
bind_layers( TCP,           WDSC,           dport=5040)
