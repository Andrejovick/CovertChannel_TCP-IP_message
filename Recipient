import sys
from scapy.all import *

def getMessage(packet):
	ttl = packet[IP].ttl
	if ttl == 210:
		list = packet['TCP'].seq
		sys.stdout.write(decryptMessage(list))

def decryptMessage(list):
	list -= 12650
	list = chr(list)
	return list

if __name__ == "__main__":
	sniff(filter="tcp", prn=getMessage)
