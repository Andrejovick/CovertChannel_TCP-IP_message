import sys
import random
from scapy.all import *

def realPacket(destIP, destPort, sprava):
    sprava = ord(sprava)
    destPort = int(destPort)
    craftedPacket = IP(src=getSpoofedIP(), dst=destIP, ttl=210)/TCP(seq=encryptMessage(sprava), dport=destPort, flags="SA")
    return craftedPacket

def fakePacket(destIP, destPort):
    destPort = int(destPort)
    craftedPacket = IP(src=getSpoofedIP(), dst=destIP, ttl=72)/TCP(dport=destPort, flags="SA")
    return craftedPacket

def getSpoofedIP():
  ipAddress = socket.gethostbyname(socket.getfqdn())
  ip1, ip2, ip3, ip4 = ipAddress.split('.')
  ip4 = str(random.randint(5,25))
  ipAddress = ip1 + "." + ip2 + "." + ip3 + "." + ip4
  return ipAddress

def encryptMessage(sprava):
  sprava += 12650
  return sprava

if __name__ == "__main__":
  destinationIP = input("Zadaj cielovu IP adresu: ")
  destinationPort = input("Zadaj cielovy port: ")
  if destinationPort == "":
    destinationPort = random.randint(1000,8505)
  while True:
    data = input("Zadaj spravu: ")
    data += "\n"
    print ("Posielanie spravy: " + data)
    spravaList = []
    for sprava in data:
        spravaList.append(sprava)
    boolCheck = 1
    while (boolCheck):
        time.sleep(random.randint(1,3))
        randNum = random.randint(1,2)
        if randNum == 2:
            if len(spravaList) == 0:
                boolCheck = 0
                print ("Sprava uspesne odoslana.")
            else:
                sprava = spravaList.pop(0)
                packet = realPacket(destinationIP, destinationPort, sprava)
                send(packet)
        elif len(spravaList) == 0:
              boolCheck = 0
              print ("Sprava uspesne odoslana.")
        else:
            packet = fakePacket(destinationIP, destinationPort)
            send(packet)
