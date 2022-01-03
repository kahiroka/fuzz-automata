import sys
from pwn import *
from protocolset import ProtocolSet
from fanmap import FaNmap
from mutator import Mutator
from logger import Logger

class Fuzzer():
  def __init__(self, file):
    self.ps = ProtocolSet()
    self.ps.load(file)
    self.mutator = Mutator('radamsa')
    self.logger = Logger()

  def _fuzz_oneshot(self, ip, port, proto, payloads):
    print("# oneshot mode")
    io = remote(ip, port, typ=proto)
    self.logger.log({'cmd':'con', 'ip':ip, 'port':port, 'proto':proto})
    fuzz = self.mutator.mutate(b64d(payloads[0].encode()))
    io.send(fuzz)
    self.logger.log({'cmd':'fuz', 'data':b64e(fuzz)})
    try:
      ret = io.recvrepeat(0.2)
    except EOFError:
      pass
    finally:
      io.close()
      self.logger.log({'cmd':'dis'})

  def _fuzz_sequence(self, ip, port, proto, payloads, pileup):
    print("# sequence mode")
    # augmentation option
    for i in range(int(pileup)):
      payloads.extend(payloads)
    if pileup > 0:
      print("pileup: 2^" + str(pileup))

    io = remote(ip, port, typ=proto)
    self.logger.log({'cmd':'con', 'ip':ip, 'port':port, 'proto':proto})

    # heuristic: shallow-deep fuzzing
    for i in range(len(payloads)):
      for j in range(len(payloads)):
        if j < i:
          fuzz = b64d(payloads[j].encode())
        else:
          fuzz = self.mutator.mutate(b64d(payloads[j].encode()))

        try:
          io.send(fuzz)
          self.logger.log({'cmd':'fuz', 'data':b64e(fuzz)})
          ret = io.recvrepeat(0.2)
        except EOFError:
          print("EOFError")
          break

    io.close()
    self.logger.log({'cmd':'dis'})

  def run(self, ip, port=None, proto=None, pileup=False):
    print("Protocol Set: " + str(self.ps.get_ports()))
    if port == None:
      fn = FaNmap()
      active_ports = fn.nmap(ip, self.ps.get_ports())
      print("Active Ports: " + str(active_ports))
      if len(active_ports) == 0:
        print("no target port")
        return
    else:
      active_ports = {'tcp':[], 'udp':[]}
      if proto == None:
        active_ports['tcp'].append(port)
        active_ports['udp'].append(port)
      else:
        active_ports[proto].append(port)

    self.logger.enable()
    while True:
      for p in self.ps.get_protocols():
        dport = p.get_dport()
        proto = p.get_proto()
        typ = p.get_type()
        if dport in active_ports[proto]:
          print(dport + "/" + proto)
          payloads = p.get_payloads()
          for sport in payloads:
            if typ == 'oneshots':
              for i in range(10):
                self._fuzz_oneshot(ip, dport, proto, payloads[sport])
            elif typ == 'sequence':
              self._fuzz_sequence(ip, dport, proto, payloads[sport], pileup)

def main():
  if len(sys.argv) == 3:
    seed_file = sys.argv[1]
    target_ip = sys.argv[2]

    fuzzer = Fuzzer(seed_file)
    try:
      fuzzer.run(target_ip)
    except KeyboardInterrupt:
      print("interrupted")
  else:
    print("python3 ./fuzzer.py seed_file target_ip")

if __name__ == '__main__':
  main()
