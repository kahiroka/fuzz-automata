from scapy.all import *
from base64 import b64encode as b64e
import sys
from .protocol import Protocol
from .protocolset import ProtocolSet

class ProtocolExtractor():
  def __init__(self, pcap, dstip, inc_mcast=False):
    packets = rdpcap(pcap)
    self.protocols = {} # key: dport

    flags = {}
    for packet in packets:
      #print(packet.show(dump=True))
      ip = packet.payload
      if IP in packet and inc_mcast and int(packet.dst[:2],16) & 0x01 and ip.src != dstip:
        mcast = True
      else:
        mcast = False
      if IP in packet and (ip.dst == dstip or mcast):
        if ip.proto == 6 or ip.proto == 17: # tcp or udp

          # ip fragment
          if ip.id in flags:
            #print("# fragment")
            sport, dport = flags[ip.id].split(':')
            self.protocols[dport].append(b64e(bytes(ip.payload)).decode(), sport, True)
            if ip.flags != 'MF':
              #print("# end of fragment")
              flags.pop(ip.id)
            continue
          elif ip.flags == 'MF':
            #print("# begin of fragment")
            flags[ip.id] = str(ip.payload.sport) + ':' + str(ip.payload.dport)
            #print(flags[ip.id])

          xxp = ip.payload
          sport = str(xxp.sport)
          dport = str(xxp.dport)

          tag = ip.src+':'+sport
          if ip.proto == 6 and xxp.flags == 0x12: # SYN,ACK
            flags[tag] = 'ignore' # ignore client side port

          if len(xxp.payload) > 0:
            payload = bytes(xxp.payload)
            proto = 'tcp' if ip.proto == 6 else 'udp'

            if tag in flags and flags[tag] == 'ignore':
              continue

            if not dport in self.protocols:
              self.protocols[dport] = Protocol(name='unknown', proto=proto, dport=dport, mcast=mcast)
            if tag in flags and flags[tag] == 'concat': # concat segments
              flags.pop(tag)
              self.protocols[dport].append(b64e(payload).decode(), sport, True)
            else:
              self.protocols[dport].append(b64e(payload).decode(), sport)

            if proto == 'tcp' and not xxp.flags & 0x08: # simple logic using psh
              flags[tag] = 'concat'

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

