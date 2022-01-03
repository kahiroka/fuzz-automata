from scapy.all import *
from base64 import b64encode as b64e
import sys
from protocol import Protocol
from protocolset import ProtocolSet

class ProtocolExtractor():
  def __init__(self, pcap, dstip):
    packets = rdpcap(pcap)
    self.protocols = {} # key: dport

    for packet in packets:
      ip = packet.payload
      if IP in packet and ip.dst == dstip:
        if ip.proto == 6 or ip.proto == 17: # tcp or udp
          xxp = ip.payload
          if len(xxp.payload) > 0 and len(packet) < 1514: # FIXME
            payload = bytes(xxp.payload)
            sport = str(xxp.sport)
            dport = str(xxp.dport)
            proto = 'tcp' if ip.proto == 6 else 'udp'

            if not dport in self.protocols:
              self.protocols[dport] = Protocol(name='unknown', proto=proto, dport=dport)
            self.protocols[dport].append(b64e(payload).decode(), sport)

  def save(self, file):
    ps = ProtocolSet(name='unknown')
    for dport in self.protocols:
      ps.append(self.protocols[dport])
    ps.save(file)

def main():
  if len(sys.argv) == 4:
    inpcap = sys.argv[1]
    outjson = sys.argv[2]
    targetip = sys.argv[3]

    try:
      pe = ProtocolExtractor(inpcap, targetip)
      pe.save(outjson)
    except FileNotFoundError:
      print("pcap file not found")
  else:
    print("python3 ./protocolextractor.py in.pcap out.json target_ip")

if __name__ == '__main__':
  main()
