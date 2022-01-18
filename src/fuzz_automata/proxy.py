from pwn import *
import sys
from .logger import Logger
from .protocolset import ProtocolSet

class Proxy():
  def __init__(self, seedfile, target_ip, proxy='localhost:8080'):
    self.proto = ProtocolSet()
    self.proto.load(seedfile)
    self.target_ip = target_ip
    (self.proxy_ip, self.proxy_port) = proxy.split(':')

  def run(self):
    methods = ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH')
    proto = self.proto.get_protocols()
    for p in proto:
      dport = p['dport']
      proto = p['proto']
      if proto == 'udp':
        continue
      payloads = p['payloads']

      for pl in payloads:
        for data in payloads[pl]:
          try:
            text = b64d(data.encode()).decode()
          except UnicodeDecodeError:
            continue

          for method in methods:
            if text.startswith(method):
              text = text.replace(method + ' ', method + ' http://' + self.target_ip + ':' + dport)

              io = remote(self.proxy_ip, self.proxy_port, typ=proto)
              io.send(text.encode())
              try:
                ret = io.recvrepeat(0.2)
              except EOFError:
                pass
              finally:
                io.close()

def main():
  if len(sys.argv) == 4:
    seed_file = sys.argv[1]
    target_ip = sys.argv[2]
    proxy_url = sys.argv[3]

    player = Proxy(seed_file, target_ip, proxy_url)
    player.run()
  else:
    print("python3 ./proxy.py seedfile target_ip proxy")

if __name__ == '__main__':
  main()
